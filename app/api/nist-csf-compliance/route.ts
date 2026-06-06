import { pool } from "@/lib/db";
import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

type ComplianceStatus =
  | "compliant"
  | "partial"
  | "non_compliant"
  | "not_assessed";

type OrganizationRow = Record<string, unknown> | null;
type AssetRow = Record<string, unknown>;
type RiskRow = {
  risk_register_id: number;
  risk_code: string | null;
  risk_title: string;
  risk_description: string | null;
  nist_csf_function: string | null;
  nist_csf_category: string | null;
  asset_id: number | null;
  asset_name: string | null;
  asset_type: string | null;
  status: string | null;
  risk_owner: string | null;
  risk_treatment: string | null;
  risk_score: number | null;
  risk_level: string | null;
  residual_risk_score: number | null;
  residual_risk_level: string | null;
};

type AssessmentRow = {
  subcategory_id: string;
  nist_function: string | null;
  function_code: string | null;
  category_name: string | null;
  category_code: string | null;
  outcome_description: string | null;
  current_tier: number | null;
  target_tier: number | null;
  gap: number | null;
  risk_score: number | null;
  risk_level: string | null;
  primary_owner: string | null;
  stakeholders: string | null;
  tools: string | null;
  control_links: string | null;
  status: string | null;
  target_date: string | null;
};

type ControlRow = {
  control_id: string;
  control_name: string;
  nist_function: string | null;
  category_code: string | null;
  control_status: string | null;
  csf_subcategory_ids: string | null;
  primary_tools: string | null;
  control_owner_role: string | null;
};

type PolicySummary = {
  totalRequired: number;
  approvedCount: number;
  pendingCount: number;
  draftCount: number;
  compliancePct: number;
};

type AssetScope = {
  total_assets: number;
  critical_assets: number;
  sensitive_assets: number;
  internet_exposed_assets: number;
  public_without_mfa: number;
  sensitive_without_encryption: number;
  logging_gap_assets: number;
  backup_gap_assets: number;
  vuln_scan_gap_assets: number;
  edr_gap_assets: number;
  mfa_coverage: number;
  encryption_coverage: number;
  logging_coverage: number;
  backup_coverage: number;
  vuln_scan_coverage: number;
  edr_coverage: number;
};

type DerivedSignal = {
  current_tier: number;
  target_tier: number;
  evidence: string;
  source: "organization" | "assets" | "organization_assets" | "risk_controls";
  owner: string | null;
  action: string;
  affected_assets: string[];
};

type NormalizedControl = {
  control_id: string;
  control_name: string;
  status: string | null;
  implemented: boolean;
  tools: string | null;
  owner: string | null;
};

type ComplianceRow = {
  subcategory_id: string;
  title: string;
  outcome: string;
  nist_function: string;
  function_code: string;
  category_code: string;
  category_name: string;
  status: ComplianceStatus;
  status_reason: string;
  current_tier: number | null;
  target_tier: number | null;
  gap: number;
  source: string;
  evidence: string[];
  owner: string | null;
  target_date: string | null;
  risk_score: number | null;
  risk_level: string | null;
  implemented_controls: number;
  recommended_controls: number;
  controls: NormalizedControl[];
  risks: RiskRow[];
  affected_assets: string[];
  recommended_action: string;
};

const FUNCTION_BY_CODE: Record<string, string> = {
  GV: "Govern",
  ID: "Identify",
  PR: "Protect",
  DE: "Detect",
  RS: "Respond",
  RC: "Recover",
};

const FUNCTION_ORDER = ["Govern", "Identify", "Protect", "Detect", "Respond", "Recover"];

const FUNCTION_LABELS: Record<string, string> = {
  Засаглал: "Govern",
  Тодорхойлох: "Identify",
  Таних: "Identify",
  Хамгаалах: "Protect",
  Илрүүлэх: "Detect",
  "Хариу арга хэмжээ авах": "Respond",
  "Хариу үйлдэл": "Respond",
  Сэргээх: "Recover",
};

const CATEGORY_NAMES: Record<string, string> = {
  "GV.OC": "Organizational Context",
  "GV.RM": "Risk Management Strategy",
  "GV.RR": "Roles, Responsibilities, and Authorities",
  "GV.PO": "Policy",
  "GV.OV": "Oversight",
  "GV.SC": "Cybersecurity Supply Chain Risk Management",
  "ID.AM": "Asset Management",
  "ID.RA": "Risk Assessment",
  "ID.IM": "Improvement",
  "PR.AA": "Identity Management, Authentication, and Access Control",
  "PR.AT": "Awareness and Training",
  "PR.DS": "Data Security",
  "PR.PS": "Platform Security",
  "PR.IR": "Technology Infrastructure Resilience",
  "DE.CM": "Continuous Monitoring",
  "DE.AE": "Adverse Event Analysis",
  "RS.MA": "Incident Management",
  "RS.AN": "Incident Analysis",
  "RS.CO": "Incident Response Reporting and Communication",
  "RS.MI": "Incident Mitigation",
  "RC.RP": "Incident Recovery Plan Execution",
  "RC.CO": "Incident Recovery Communication",
};

async function tableExists(tableName: string) {
  const result = await pool.query("SELECT to_regclass($1) AS table_name", [
    `public.${tableName}`,
  ]);
  return Boolean(result.rows[0]?.table_name);
}

async function columnExists(tableName: string, columnName: string) {
  const result = await pool.query(
    `SELECT 1
       FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = $1
        AND column_name = $2
      LIMIT 1`,
    [tableName, columnName],
  );
  return result.rows.length > 0;
}

async function getOrganization(): Promise<OrganizationRow> {
  if (!(await tableExists("organization_information"))) return null;
  const result = await pool.query("SELECT * FROM organization_information LIMIT 1");
  return result.rows[0] ?? null;
}

async function getAssets(): Promise<AssetRow[]> {
  if (!(await tableExists("assets"))) return [];
  const result = await pool.query("SELECT * FROM assets");
  return result.rows.filter((asset) => normalize(asset.status) !== "retired");
}

async function getAssessmentRows(): Promise<AssessmentRow[]> {
  if (!(await tableExists("csf_subcategories"))) return [];
  const result = await pool.query(`
    SELECT *
      FROM csf_subcategories
     ORDER BY function_code, category_code, subcategory_id
  `);
  return result.rows;
}

async function getControls(): Promise<ControlRow[]> {
  if (!(await tableExists("nist_controls"))) return [];
  const [
    hasNistFunction,
    hasNistCsfFunction,
    hasCategoryCode,
    hasNistCsfCategory,
    hasControlStatus,
    hasImplementationStatus,
    hasSubcategoryIds,
    hasPrimaryTools,
    hasControlOwnerRole,
    hasIsActive,
  ] = await Promise.all([
    columnExists("nist_controls", "nist_function"),
    columnExists("nist_controls", "nist_csf_function"),
    columnExists("nist_controls", "category_code"),
    columnExists("nist_controls", "nist_csf_category"),
    columnExists("nist_controls", "control_status"),
    columnExists("nist_controls", "implementation_status"),
    columnExists("nist_controls", "csf_subcategory_ids"),
    columnExists("nist_controls", "primary_tools"),
    columnExists("nist_controls", "control_owner_role"),
    columnExists("nist_controls", "is_active"),
  ]);
  const result = await pool.query(`
    SELECT control_id,
           control_name,
           ${
             hasNistFunction
               ? "nist_function"
               : hasNistCsfFunction
                 ? "nist_csf_function"
                 : "NULL::varchar"
           } AS nist_function,
           ${
             hasCategoryCode
               ? "category_code"
               : hasNistCsfCategory
                 ? "nist_csf_category"
                 : "NULL::varchar"
           } AS category_code,
           ${
             hasControlStatus
               ? "control_status"
               : hasImplementationStatus
                 ? "implementation_status"
                 : "NULL::varchar"
           } AS control_status,
           ${hasSubcategoryIds ? "csf_subcategory_ids" : "NULL::text AS csf_subcategory_ids"},
           ${hasPrimaryTools ? "primary_tools" : "NULL::text"} AS primary_tools,
           ${
             hasControlOwnerRole ? "control_owner_role" : "NULL::varchar"
           } AS control_owner_role
      FROM nist_controls
     ${hasIsActive ? "WHERE COALESCE(is_active, TRUE) = TRUE" : ""}
     ORDER BY category_code, control_id
  `);
  return result.rows;
}

async function getRisks(): Promise<RiskRow[]> {
  if (!(await tableExists("risk_register"))) return [];
  const hasRiskAnalysis = await tableExists("risk_analysis");
  const hasAssets = await tableExists("assets");
  const [
    hasRiskCode,
    hasLegacyRiskId,
    hasRiskDescription,
    hasNistFunction,
    hasNistCategory,
    hasAssetId,
    hasStatus,
    hasRiskOwner,
    hasRiskTreatment,
    hasRiskLevel,
    hasAssetName,
    hasAssetType,
    hasRaRiskRegisterId,
    hasRaRiskId,
    hasRaInherentScore,
    hasRaInherentLevel,
    hasRaScore,
    hasRaLevel,
    hasRaResidualScore,
    hasRaResidualLevel,
  ] = await Promise.all([
    columnExists("risk_register", "risk_code"),
    columnExists("risk_register", "risk_id"),
    columnExists("risk_register", "risk_description"),
    columnExists("risk_register", "nist_csf_function"),
    columnExists("risk_register", "nist_csf_category"),
    columnExists("risk_register", "asset_id"),
    columnExists("risk_register", "status"),
    columnExists("risk_register", "risk_owner"),
    columnExists("risk_register", "risk_treatment"),
    columnExists("risk_register", "risk_level"),
    hasAssets ? columnExists("assets", "asset_name") : Promise.resolve(false),
    hasAssets ? columnExists("assets", "asset_type") : Promise.resolve(false),
    hasRiskAnalysis
      ? columnExists("risk_analysis", "risk_register_id")
      : Promise.resolve(false),
    hasRiskAnalysis ? columnExists("risk_analysis", "risk_id") : Promise.resolve(false),
    hasRiskAnalysis
      ? columnExists("risk_analysis", "inherent_risk_score")
      : Promise.resolve(false),
    hasRiskAnalysis
      ? columnExists("risk_analysis", "inherent_risk_level")
      : Promise.resolve(false),
    hasRiskAnalysis ? columnExists("risk_analysis", "risk_score") : Promise.resolve(false),
    hasRiskAnalysis ? columnExists("risk_analysis", "risk_level") : Promise.resolve(false),
    hasRiskAnalysis
      ? columnExists("risk_analysis", "residual_risk_score")
      : Promise.resolve(false),
    hasRiskAnalysis
      ? columnExists("risk_analysis", "residual_risk_level")
      : Promise.resolve(false),
  ]);

  const riskAnalysisJoin = hasRiskAnalysis && hasRaRiskRegisterId
    ? "LEFT JOIN risk_analysis ra ON ra.risk_register_id = rr.id"
    : hasRiskAnalysis && hasRaRiskId
      ? "LEFT JOIN risk_analysis ra ON ra.risk_id = rr.id"
    : "LEFT JOIN (SELECT NULL::integer AS risk_register_id, NULL::integer AS inherent_risk_score, NULL::text AS inherent_risk_level, NULL::integer AS risk_score, NULL::text AS risk_level, NULL::integer AS residual_risk_score, NULL::text AS residual_risk_level) ra ON false";

  const assetsJoin = hasAssets && hasAssetId
    ? "LEFT JOIN assets a ON a.id = rr.asset_id"
    : "LEFT JOIN (SELECT NULL::integer AS id, NULL::text AS asset_name, NULL::text AS asset_type) a ON false";
  const riskCodeExpr = hasRiskCode
    ? "rr.risk_code"
    : hasLegacyRiskId
      ? "rr.risk_id"
      : "NULL::varchar";
  const riskScoreExpr = `COALESCE(${
    hasRaInherentScore ? "ra.inherent_risk_score" : "NULL"
  }, ${hasRaScore ? "ra.risk_score" : "NULL"}, 0)::int`;
  const riskLevelExpr = `COALESCE(${
    hasRaInherentLevel ? "ra.inherent_risk_level" : "NULL"
  }, ${hasRaLevel ? "ra.risk_level" : "NULL"}, ${
    hasRiskLevel ? "rr.risk_level" : "NULL"
  }, 'Unknown')`;

  const result = await pool.query(`
    SELECT rr.id AS risk_register_id,
           ${riskCodeExpr} AS risk_code,
           rr.risk_title,
           ${hasRiskDescription ? "rr.risk_description" : "NULL::text"} AS risk_description,
           ${hasNistFunction ? "rr.nist_csf_function" : "NULL::varchar"} AS nist_csf_function,
           ${hasNistCategory ? "rr.nist_csf_category" : "NULL::varchar"} AS nist_csf_category,
           ${hasAssetId ? "rr.asset_id" : "NULL::integer"} AS asset_id,
           ${hasStatus ? "rr.status" : "NULL::varchar"} AS status,
           ${hasRiskOwner ? "rr.risk_owner" : "NULL::varchar"} AS risk_owner,
           ${hasRiskTreatment ? "rr.risk_treatment" : "NULL::varchar"} AS risk_treatment,
           ${hasAssetName ? "a.asset_name" : "NULL::varchar"} AS asset_name,
           ${hasAssetType ? "a.asset_type" : "NULL::varchar"} AS asset_type,
           ${riskScoreExpr} AS risk_score,
           ${riskLevelExpr} AS risk_level,
           ${hasRaResidualScore ? "ra.residual_risk_score" : "NULL::integer"} AS residual_risk_score,
           ${hasRaResidualLevel ? "ra.residual_risk_level" : "NULL::varchar"} AS residual_risk_level
      FROM risk_register rr
      ${riskAnalysisJoin}
      ${assetsJoin}
     ${
       hasStatus
         ? "WHERE LOWER(COALESCE(rr.status, 'open')) NOT IN ('closed', 'accepted', 'resolved')"
         : ""
     }
  `);
  return result.rows;
}

async function getPolicySummary(): Promise<PolicySummary> {
  if (!(await tableExists("policies"))) {
    return {
      totalRequired: 0,
      approvedCount: 0,
      pendingCount: 0,
      draftCount: 0,
      compliancePct: 0,
    };
  }
  const [hasIsRequired, hasStatus, hasNextReviewAt] = await Promise.all([
    columnExists("policies", "is_required"),
    columnExists("policies", "status"),
    columnExists("policies", "next_review_at"),
  ]);
  const requiredPredicate = hasIsRequired ? "is_required = TRUE" : "TRUE";
  const approvedPredicate = hasStatus
    ? `LOWER(status) = 'approved' ${
        hasNextReviewAt ? "AND (next_review_at IS NULL OR next_review_at > NOW())" : ""
      }`
    : "FALSE";
  const pendingPredicate = hasStatus ? "LOWER(status) = 'pending approval'" : "FALSE";
  const draftPredicate = hasStatus ? "LOWER(status) = 'draft'" : "FALSE";

  const result = await pool.query(`
    SELECT COUNT(*) FILTER (WHERE ${requiredPredicate})::int AS total_required,
           COUNT(*) FILTER (
             WHERE ${requiredPredicate}
               AND ${approvedPredicate}
           )::int AS approved_count,
           COUNT(*) FILTER (WHERE ${requiredPredicate} AND ${pendingPredicate})::int AS pending_count,
           COUNT(*) FILTER (WHERE ${requiredPredicate} AND ${draftPredicate})::int AS draft_count
      FROM policies
  `);

  const row = result.rows[0] ?? {};
  const totalRequired = Number(row.total_required ?? 0);
  const approvedCount = Number(row.approved_count ?? 0);

  return {
    totalRequired,
    approvedCount,
    pendingCount: Number(row.pending_count ?? 0),
    draftCount: Number(row.draft_count ?? 0),
    compliancePct:
      totalRequired > 0 ? Math.round((approvedCount / totalRequired) * 100) : 0,
  };
}

async function flattenSubcategories() {
  const result = await pool.query<{
    subcategory_id: string;
    title: string;
    outcome_description: string;
    category_code: string;
    category_name: string;
    function_code: string;
    nist_function: string;
  }>(`
    SELECT subcategory_id, title, outcome_description,
           category_code, category_name, function_code, nist_function
      FROM csf_subcategories
     ORDER BY function_code, category_code, subcategory_id
  `);
  return result.rows.map((row) => ({
    code: row.subcategory_id,
    title: row.title ?? row.subcategory_id,
    outcome: row.outcome_description ?? "",
    category_code: row.category_code ?? "",
    category_name: row.category_name ?? CATEGORY_NAMES[row.category_code] ?? row.category_code,
    function_code: row.function_code ?? "",
    nist_function: normalizeNistFunction(row.function_code, row.nist_function),
  }));
}

function normalize(value: unknown) {
  return String(value ?? "").trim().toLowerCase();
}

function normalizeNistFunction(
  functionCode: string | null | undefined,
  label: string | null | undefined,
) {
  const fromCode = FUNCTION_BY_CODE[String(functionCode ?? "").toUpperCase()];
  if (fromCode) return fromCode;

  const raw = String(label ?? "").trim();
  if (FUNCTION_ORDER.includes(raw)) return raw;
  return FUNCTION_LABELS[raw] ?? "Other";
}

function bool(value: unknown) {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value !== 0;
  return ["true", "yes", "1", "enabled", "on"].includes(normalize(value));
}

function numberValue(value: unknown) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function jsonArray(value: unknown) {
  if (Array.isArray(value)) return value.map(String).filter(Boolean);
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      if (Array.isArray(parsed)) return parsed.map(String).filter(Boolean);
    } catch {
      return value
        .split(",")
        .map((part) => part.trim())
        .filter(Boolean);
    }
  }
  return [];
}

function jsonObject(value: unknown) {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return parsed && typeof parsed === "object" && !Array.isArray(parsed)
        ? (parsed as Record<string, unknown>)
        : {};
    } catch {
      return {};
    }
  }
  return {};
}

function containsAny(value: unknown, terms: string[]) {
  const text = normalize(value);
  return terms.some((term) => text.includes(term));
}

function hasAny(values: unknown[], terms: string[]) {
  return values.some((value) => containsAny(value, terms));
}

function assetName(asset: AssetRow) {
  return String(asset.asset_name ?? asset.asset_code ?? "Нэргүй хөрөнгө");
}

function isCriticalAsset(asset: AssetRow) {
  return (
    containsAny(asset.criticality, ["critical", "high", "tier 0", "tier 1", "mission"]) ||
    bool(asset.supports_critical_service)
  );
}

function isSensitiveAsset(asset: AssetRow) {
  return containsAny(asset.data_classification, [
    "restricted",
    "confidential",
    "sensitive",
    "personal",
    "pii",
    "phi",
    "pci",
    "нууц",
  ]);
}

function isInternetExposed(asset: AssetRow) {
  return (
    bool(asset.internet_exposed) ||
    containsAny(asset.access_level, ["public web", "public api", "internet", "external"])
  );
}

function hasStrongAuth(asset: AssetRow) {
  return (
    bool(asset.mfa_enabled) ||
    containsAny(asset.authentication_method, ["mfa", "sso", "federated"])
  );
}

function fieldCoverage(assets: AssetRow[], predicate: (asset: AssetRow) => boolean) {
  if (assets.length === 0) return 0;
  return Math.round((assets.filter(predicate).length / assets.length) * 100);
}

function tierFromCoverage(percent: number) {
  if (percent >= 90) return 4;
  if (percent >= 70) return 3;
  if (percent >= 40) return 2;
  if (percent > 0) return 1;
  return 0;
}

function tierFromPolicy(summary: PolicySummary) {
  if (summary.totalRequired === 0) return 0;
  if (summary.compliancePct >= 90) return 4;
  if (summary.compliancePct >= 70) return 3;
  if (summary.compliancePct >= 30) return 2;
  return 1;
}

function riskRank(level: string | null | undefined) {
  switch (normalize(level)) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}

function riskSort(a: RiskRow, b: RiskRow) {
  return (
    riskRank(b.residual_risk_level ?? b.risk_level) -
      riskRank(a.residual_risk_level ?? a.risk_level) ||
    Number(b.residual_risk_score ?? b.risk_score ?? 0) -
      Number(a.residual_risk_score ?? a.risk_score ?? 0)
  );
}

function assetScope(assets: AssetRow[]): AssetScope {
  const publicWithoutMfa = assets.filter(
    (asset) => isInternetExposed(asset) && !hasStrongAuth(asset),
  );
  const sensitiveWithoutEncryption = assets.filter(
    (asset) => isSensitiveAsset(asset) && !bool(asset.encryption_enabled),
  );
  const loggingGapAssets = assets.filter((asset) => !bool(asset.logging_enabled));
  const backupGapAssets = assets.filter(
    (asset) => isCriticalAsset(asset) && !bool(asset.backup_enabled),
  );
  const vulnScanGapAssets = assets.filter((asset) => !bool(asset.vuln_scanning));
  const edrGapAssets = assets.filter((asset) => !bool(asset.edr_endpoint_security));

  return {
    total_assets: assets.length,
    critical_assets: assets.filter(isCriticalAsset).length,
    sensitive_assets: assets.filter(isSensitiveAsset).length,
    internet_exposed_assets: assets.filter(isInternetExposed).length,
    public_without_mfa: publicWithoutMfa.length,
    sensitive_without_encryption: sensitiveWithoutEncryption.length,
    logging_gap_assets: loggingGapAssets.length,
    backup_gap_assets: backupGapAssets.length,
    vuln_scan_gap_assets: vulnScanGapAssets.length,
    edr_gap_assets: edrGapAssets.length,
    mfa_coverage: fieldCoverage(assets, hasStrongAuth),
    encryption_coverage: fieldCoverage(assets, (asset) =>
      bool(asset.encryption_enabled),
    ),
    logging_coverage: fieldCoverage(assets, (asset) => bool(asset.logging_enabled)),
    backup_coverage: fieldCoverage(assets, (asset) => bool(asset.backup_enabled)),
    vuln_scan_coverage: fieldCoverage(assets, (asset) => bool(asset.vuln_scanning)),
    edr_coverage: fieldCoverage(assets, (asset) => bool(asset.edr_endpoint_security)),
  };
}

function getOrganizationSignals(organization: OrganizationRow) {
  const complianceRequirements = jsonArray(organization?.compliance_requirements);
  const reviewTriggers = jsonArray(organization?.review_triggers);
  const answers = jsonObject(organization?.sensitive_data_answers);
  const cloudServices = jsonArray(answers.cloudServices);
  const regulatoryExposure = jsonArray(answers.regulatoryExposure);
  const securityCapabilities = jsonArray(answers.securityCapabilities);
  const thirdPartyDependency = String(answers.thirdPartyDependency ?? "");

  return {
    hasProfile: Boolean(organization),
    hasOrgContext: Boolean(
      organization?.organization_name &&
        organization?.industry &&
        organization?.size_category,
    ),
    complianceRequirements,
    reviewTriggers,
    cloudServices,
    regulatoryExposure,
    securityCapabilities,
    thirdPartyDependency,
    usesSensitiveData: bool(organization?.uses_sensitive_data),
    hasSensitiveRequirement:
      hasAny(complianceRequirements, [
        "gdpr",
        "hipaa",
        "pci",
        "data protection",
        "хувийн мэдээлэл",
        "мэдээлэл хамгаалах",
      ]) || regulatoryExposure.some((item) => normalize(item) !== "none"),
    riskOwner: stringOrNull(organization?.risk_owner),
    securityOwner: stringOrNull(organization?.security_owner),
    approver: stringOrNull(organization?.risk_acceptance_approver),
    hasCriticalServices: Boolean(
      stringOrNull(organization?.critical_business_services),
    ),
    hasRiskAppetite: Boolean(stringOrNull(organization?.risk_appetite)),
    hasReviewCadence: Boolean(numberValue(organization?.review_cadence_days)),
    hasThresholds:
      Object.keys(jsonObject(organization?.risk_tolerance_thresholds)).length > 0,
  };
}

function stringOrNull(value: unknown) {
  const text = String(value ?? "").trim();
  return text.length > 0 ? text : null;
}

function topAssetNames(assets: AssetRow[], predicate: (asset: AssetRow) => boolean) {
  return assets.filter(predicate).slice(0, 5).map(assetName);
}

function deriveSignals(
  organization: OrganizationRow,
  assets: AssetRow[],
  policies: PolicySummary,
  risks: RiskRow[],
) {
  const scope = assetScope(assets);
  const org = getOrganizationSignals(organization);
  const signals = new Map<string, DerivedSignal>();
  const sensitiveOrCritical =
    org.usesSensitiveData || scope.sensitive_assets > 0 || scope.critical_assets > 0;
  const thirdPartyRelevant =
    hasAny(org.cloudServices, ["google", "microsoft", "aws", "azure"]) ||
    ["few", "many", "coreDepends"].includes(org.thirdPartyDependency) ||
    assets.some((asset) => containsAny(asset.hosting, ["cloud", "saas", "vendor"]));
  const hasRisks = risks.length > 0;
  const risksWithScores = risks.filter((risk) => Number(risk.risk_score ?? 0) > 0);

  const put = (
    code: string,
    current_tier: number,
    target_tier: number,
    evidence: string,
    action: string,
    options?: Partial<DerivedSignal>,
  ) => {
    signals.set(code, {
      current_tier,
      target_tier,
      evidence,
      source: options?.source ?? "organization_assets",
      owner: options?.owner ?? org.securityOwner ?? org.riskOwner,
      action,
      affected_assets: options?.affected_assets ?? [],
    });
  };

  put(
    "GV.OC-01",
    org.hasOrgContext ? 3 : org.hasProfile ? 2 : 0,
    3,
    org.hasOrgContext
      ? "Байгууллагын нэр, салбар, хэмжээ бүртгэгдсэн."
      : "Байгууллагын үндсэн context бүрэн ороогүй байна.",
    "Байгууллагын mission, салбар, хэмжээ болон cybersecurity зорилтуудыг profile дээр бүрэн баталгаажуулна.",
    { source: "organization", owner: org.riskOwner },
  );
  put(
    "GV.OC-03",
    org.complianceRequirements.length > 0 ? 3 : org.hasProfile ? 1 : 0,
    org.hasSensitiveRequirement || sensitiveOrCritical ? 4 : 3,
    `${org.complianceRequirements.length} compliance шаардлага бүртгэгдсэн.`,
    "Хууль, зохицуулалт, гэрээний cybersecurity шаардлагуудыг бүртгэж, хариуцагч болон review давтамжтай холбоно.",
    { source: "organization", owner: org.riskOwner },
  );
  put(
    "GV.OC-04",
    org.hasCriticalServices || scope.critical_assets > 0 ? 3 : scope.total_assets > 0 ? 2 : 0,
    scope.critical_assets > 0 ? 4 : 3,
    `${scope.critical_assets} чухал хөрөнгө, ${scope.total_assets} нийт хөрөнгө бүртгэгдсэн.`,
    "Critical service болон түүнийг дэмждэг хөрөнгүүдийн нэн тэргүүний жагсаалтыг баталгаажуулна.",
    {
      source: "organization_assets",
      affected_assets: topAssetNames(assets, isCriticalAsset),
      owner: org.riskOwner,
    },
  );
  put(
    "GV.RM-01",
    org.riskOwner && org.approver ? 3 : org.riskOwner ? 2 : org.hasProfile ? 1 : 0,
    sensitiveOrCritical ? 4 : 3,
    org.riskOwner
      ? `Эрсдэл хариуцагч: ${org.riskOwner}.`
      : "Эрсдэл хариуцагч бүртгэгдээгүй.",
    "Эрсдэлийн удирдлагын зорилт, шийдвэр гаргах эрх мэдэл, баталгаажуулах эзнийг тодорхойлно.",
    { source: "organization", owner: org.riskOwner },
  );
  put(
    "GV.RM-02",
    org.hasRiskAppetite ? 3 : org.hasProfile ? 1 : 0,
    sensitiveOrCritical ? 4 : 3,
    org.hasRiskAppetite
      ? `Эрсдэлийг хүлээж авах түвшин: ${organization?.risk_appetite}.`
      : "Risk appetite бүртгэгдээгүй.",
    "Risk appetite болон tolerance босгыг critical asset, sensitive data, residual risk шийдвэрт ашиглахаар баталгаажуулна.",
    { source: "organization", owner: org.riskOwner },
  );
  put(
    "GV.RM-06",
    org.hasThresholds && org.hasReviewCadence ? 3 : org.hasThresholds ? 2 : 1,
    3,
    org.hasThresholds
      ? "Эрсдэлийн онооны threshold бүртгэгдсэн."
      : "Эрсдэлийн scoring threshold бүртгэгдээгүй.",
    "Likelihood, impact, residual risk, review давтамжийн нэг аргачлалыг байгууллагын хэмжээнд мөрдүүлнэ.",
    { source: "organization", owner: org.riskOwner },
  );
  put(
    "GV.PO-01",
    tierFromPolicy(policies),
    sensitiveOrCritical ? 4 : 3,
    policies.totalRequired > 0
      ? `${policies.approvedCount}/${policies.totalRequired} шаардлагатай бодлого approved төлөвтэй.`
      : "Шаардлагатай бодлогын бүртгэл олдсонгүй.",
    "NIST-тэй холбоотой шаардлагатай бодлогуудыг баталж, хэрэгжилт болон review хугацааг мөрдүүлнэ.",
    { source: "organization", owner: org.securityOwner ?? org.riskOwner },
  );
  put(
    "GV.PO-02",
    policies.totalRequired > 0 ? Math.max(1, tierFromPolicy(policies) - 1) : 0,
    3,
    policies.pendingCount + policies.draftCount > 0
      ? `${policies.pendingCount + policies.draftCount} бодлого draft/pending төлөвтэй.`
      : "Бодлогын review төлөв бүртгэгдээгүй эсвэл бүрэн баталгаажсан.",
    "Бодлогуудын review cadence, owner, next review огноог шинэчилж, өөрчлөлт гарсан үед дахин баталгаажуулна.",
    { source: "organization", owner: org.securityOwner ?? org.riskOwner },
  );

  if (thirdPartyRelevant) {
    put(
      "GV.SC-04",
      1,
      3,
      "Үүлэн үйлчилгээ, SaaS эсвэл vendor dependency profile/asset дээр илэрсэн.",
      "Нийлүүлэгч, SaaS, external service-ийн inventory үүсгэж, criticality болон data access-аар эрэмбэлнэ.",
      { source: "organization_assets", owner: org.riskOwner },
    );
    put(
      "GV.SC-05",
      1,
      sensitiveOrCritical ? 4 : 3,
      "Гуравдагч этгээдийн cybersecurity шаардлагын нотолгоо бүртгэгдээгүй.",
      "Нийлүүлэгчийн гэрээ, SLA, data handling, incident notification, security requirement-уудыг тодорхой болгоно.",
      { source: "organization_assets", owner: org.riskOwner },
    );
    put(
      "GV.SC-07",
      1,
      3,
      "Vendor/SaaS ашиглалт илэрсэн боловч continuous monitoring evidence байхгүй.",
      "Critical supplier-уудыг жил бүр үнэлж, өндөр эрсдэлтэй vendor дээр remediation tracker үүсгэнэ.",
      { source: "organization_assets", owner: org.riskOwner },
    );
  }

  put(
    "ID.AM-01",
    scope.total_assets > 0 ? 3 : 0,
    scope.critical_assets > 0 ? 4 : 3,
    `${scope.total_assets} хөрөнгө бүртгэгдсэн.`,
    "Hardware болон system inventory-г owner, location/hosting, criticality-тэйгээр шинэчилнэ.",
    { source: "assets" },
  );
  put(
    "ID.AM-02",
    tierFromCoverage(fieldCoverage(assets, (asset) => Boolean(asset.asset_type))),
    3,
    `${fieldCoverage(assets, (asset) => Boolean(asset.asset_type))}% хөрөнгө asset type-тэй.`,
    "Software, service, platform төрлийг бүх хөрөнгөнд бөглөж CMDB мэдээлэлтэй уялдуулна.",
    { source: "assets" },
  );
  put(
    "ID.AM-05",
    tierFromCoverage(fieldCoverage(assets, (asset) => Boolean(asset.criticality))),
    scope.critical_assets > 0 ? 4 : 3,
    `${scope.critical_assets} critical/high хөрөнгө бүртгэгдсэн.`,
    "Criticality, business value, data classification дээр үндэслэн asset priority-г баталгаажуулна.",
    {
      source: "assets",
      affected_assets: topAssetNames(assets, isCriticalAsset),
    },
  );
  put(
    "ID.AM-07",
    tierFromCoverage(fieldCoverage(assets, (asset) => Boolean(asset.data_classification))),
    sensitiveOrCritical ? 4 : 3,
    `${scope.sensitive_assets} sensitive/confidential/restricted data бүхий хөрөнгө байна.`,
    "Data classification болон data owner талбарыг бүх sensitive хөрөнгөнд бүрэн бөглөж баталгаажуулна.",
    {
      source: "assets",
      affected_assets: topAssetNames(assets, isSensitiveAsset),
    },
  );
  put(
    "ID.RA-01",
    tierFromCoverage(scope.vuln_scan_coverage),
    scope.critical_assets > 0 ? 4 : 3,
    `${scope.vuln_scan_coverage}% хөрөнгө vulnerability scanning талбартай.`,
    "Critical болон internet-facing хөрөнгүүдэд vulnerability scanning coverage-г бүрэнжүүлнэ.",
    {
      source: "assets",
      affected_assets: topAssetNames(assets, (asset) => !bool(asset.vuln_scanning)),
    },
  );
  put(
    "ID.RA-04",
    hasRisks ? (risksWithScores.length === risks.length ? 3 : 2) : 0,
    3,
    `${risks.length} эрсдэл бүртгэгдсэн, ${risksWithScores.length} нь оноотой.`,
    "Risk scenario бүрт likelihood, impact, inherent болон residual score-г бүрэн бөглөнө.",
    { source: "risk_controls", owner: org.riskOwner },
  );
  put(
    "ID.RA-05",
    hasRisks ? 3 : 0,
    3,
    `${risks.length} risk register бичлэг идэвхтэй байна.`,
    "Threat, vulnerability, likelihood, impact мэдээллийг нэг risk record-д уялдуулж, high/critical эрсдэлийг review-д оруулна.",
    { source: "risk_controls", owner: org.riskOwner },
  );
  put(
    "PR.AA-01",
    tierFromCoverage(scope.mfa_coverage),
    scope.internet_exposed_assets > 0 || sensitiveOrCritical ? 4 : 3,
    `${scope.mfa_coverage}% хөрөнгө MFA/strong auth coverage-тэй.`,
    "Internet-facing болон critical хөрөнгүүдэд MFA/SSO-г албажуулж, exception бүрийг баталгаажуулна.",
    {
      source: "assets",
      affected_assets: topAssetNames(
        assets,
        (asset) => isInternetExposed(asset) && !hasStrongAuth(asset),
      ),
    },
  );
  put(
    "PR.AA-03",
    tierFromCoverage(scope.mfa_coverage),
    scope.internet_exposed_assets > 0 ? 4 : 3,
    `${scope.public_without_mfa} public-facing хөрөнгө MFA/strong auth gap-тай.`,
    "User, service, asset authentication requirement-г internet-facing asset дээр enforce хийнэ.",
    {
      source: "assets",
      affected_assets: topAssetNames(
        assets,
        (asset) => isInternetExposed(asset) && !hasStrongAuth(asset),
      ),
    },
  );
  put(
    "PR.AA-05",
    tierFromCoverage(fieldCoverage(assets, (asset) => Boolean(asset.access_level))),
    3,
    `${fieldCoverage(assets, (asset) => Boolean(asset.access_level))}% хөрөнгө access level-тэй.`,
    "Access level, entitlement owner, privileged access review-г хөрөнгө бүрт бүртгэнэ.",
    { source: "assets" },
  );
  put(
    "PR.DS-01",
    tierFromCoverage(scope.encryption_coverage),
    sensitiveOrCritical ? 4 : 3,
    `${scope.sensitive_without_encryption} sensitive хөрөнгө encryption gap-тай.`,
    "Sensitive data хадгалдаг хөрөнгүүд дээр encryption-at-rest болон key ownership-г баталгаажуулна.",
    {
      source: "assets",
      affected_assets: topAssetNames(
        assets,
        (asset) => isSensitiveAsset(asset) && !bool(asset.encryption_enabled),
      ),
    },
  );
  put(
    "PR.DS-11",
    tierFromCoverage(scope.backup_coverage),
    scope.critical_assets > 0 ? 4 : 3,
    `${scope.backup_gap_assets} critical хөрөнгө backup gap-тай.`,
    "Critical хөрөнгүүдийн backup, restore test, RTO/RPO нотолгоог бүрдүүлнэ.",
    {
      source: "assets",
      affected_assets: topAssetNames(
        assets,
        (asset) => isCriticalAsset(asset) && !bool(asset.backup_enabled),
      ),
    },
  );
  put(
    "PR.PS-04",
    tierFromCoverage(scope.logging_coverage),
    scope.internet_exposed_assets > 0 ? 4 : 3,
    `${scope.logging_coverage}% хөрөнгө logging enabled төлөвтэй.`,
    "Critical болон public хөрөнгийн логийг SIEM/central monitoring руу холбож retention-г тогтооно.",
    {
      source: "assets",
      affected_assets: topAssetNames(assets, (asset) => !bool(asset.logging_enabled)),
    },
  );
  put(
    "PR.PS-05",
    tierFromCoverage(scope.edr_coverage),
    scope.internet_exposed_assets > 0 || scope.critical_assets > 0 ? 4 : 3,
    `${scope.edr_coverage}% хөрөнгө endpoint/security tool бүртгэлтэй.`,
    "Endpoint protection, application allowlisting эсвэл unauthorized software prevention control-г хамруулах.",
    {
      source: "assets",
      affected_assets: topAssetNames(assets, (asset) => !bool(asset.edr_endpoint_security)),
    },
  );
  put(
    "DE.CM-01",
    tierFromCoverage(scope.logging_coverage),
    scope.internet_exposed_assets > 0 ? 4 : 3,
    `${scope.logging_gap_assets} хөрөнгө monitoring/logging gap-тай.`,
    "Network, cloud, endpoint telemetry-г central monitoring руу нэгтгэж alert use case үүсгэнэ.",
    {
      source: "assets",
      affected_assets: topAssetNames(assets, (asset) => !bool(asset.logging_enabled)),
    },
  );
  put(
    "DE.CM-09",
    tierFromCoverage(scope.logging_coverage),
    scope.critical_assets > 0 ? 4 : 3,
    `${scope.logging_coverage}% runtime/asset monitoring coverage.`,
    "Runtime, application, database, cloud activity monitoring-г critical asset дээр бүрэнжүүлнэ.",
    {
      source: "assets",
      affected_assets: topAssetNames(assets, (asset) => !bool(asset.logging_enabled)),
    },
  );
  put(
    "RS.MA-01",
    hasAny(org.reviewTriggers, ["incident"]) ? 3 : hasRisks ? 2 : 1,
    risks.some((risk) => riskRank(risk.risk_level) >= 3) ? 4 : 3,
    `${risks.filter((risk) => riskRank(risk.risk_level) >= 3).length} high/critical эрсдэл идэвхтэй.`,
    "Incident response plan-ийн owner, escalation, tabletop/test evidence-г high/critical risk-тэй уялдуулна.",
    { source: "organization", owner: org.securityOwner ?? org.riskOwner },
  );
  put(
    "RS.MA-03",
    hasRisks ? 2 : 0,
    3,
    `${risks.length} идэвхтэй эрсдэл risk register-д байна.`,
    "Incident severity болон business impact prioritization criteria-г risk score, asset criticality-тэй уялдуулна.",
    { source: "risk_controls", owner: org.securityOwner ?? org.riskOwner },
  );
  put(
    "RC.RP-01",
    tierFromCoverage(scope.backup_coverage),
    scope.critical_assets > 0 ? 4 : 3,
    `${scope.backup_coverage}% хөрөнгө backup enabled төлөвтэй.`,
    "Critical asset бүрт recovery plan, restore owner, RTO/RPO test result-г бүртгэнэ.",
    {
      source: "assets",
      affected_assets: topAssetNames(
        assets,
        (asset) => isCriticalAsset(asset) && !bool(asset.backup_enabled),
      ),
    },
  );
  put(
    "RC.RP-03",
    tierFromCoverage(
      fieldCoverage(
        assets,
        (asset) => Boolean(asset.rto_hours) && Boolean(asset.rpo_hours),
      ),
    ),
    scope.critical_assets > 0 ? 4 : 3,
    `${fieldCoverage(assets, (asset) => Boolean(asset.rto_hours) && Boolean(asset.rpo_hours))}% хөрөнгө RTO/RPO-той.`,
    "Сэргээсэн asset болон data-г production-д буцаахаас өмнө validation checklist, owner, evidence-тэй болгоно.",
    { source: "assets" },
  );

  return { signals, scope, org };
}

function controlImplemented(status: string | null | undefined) {
  const normalized = normalize(status);
  return normalized.includes("implement") && !normalized.startsWith("not");
}

function subcategoryIds(control: ControlRow) {
  return String(control.csf_subcategory_ids ?? "")
    .split(/[;,]/)
    .map((part) => part.trim())
    .filter(Boolean);
}

function controlsForSubcategory(controls: ControlRow[], code: string, categoryCode: string) {
  const exact = controls.filter((control) => subcategoryIds(control).includes(code));
  if (exact.length > 0) return exact;
  return controls.filter((control) => control.category_code === categoryCode);
}

function risksForSubcategory(risks: RiskRow[], code: string, categoryCode: string) {
  return risks
    .filter((risk) => {
      const category = risk.nist_csf_category;
      const baseCategory = category?.includes("-")
        ? category.substring(0, category.lastIndexOf("-"))
        : (category ?? "");
      return category === code || baseCategory === categoryCode;
    })
    .sort(riskSort);
}

function determineStatus(input: {
  currentTier: number | null;
  targetTier: number | null;
  hasAssessment: boolean;
  implementedControls: number;
  risks: RiskRow[];
  gap: number;
  hasDerived: boolean;
}) {
  const highRisk = input.risks.some((risk) =>
    riskRank(risk.residual_risk_level ?? risk.risk_level) >= 3,
  );

  if (input.currentTier === null && !input.hasAssessment && !input.hasDerived) {
    return input.implementedControls > 0 ? "partial" : "not_assessed";
  }

  if (input.gap > 0 || highRisk) return "non_compliant";
  if (
    input.currentTier !== null &&
    input.targetTier !== null &&
    input.currentTier >= input.targetTier
  ) {
    return "compliant";
  }
  return input.implementedControls > 0 ? "partial" : "not_assessed";
}

function statusReason(row: {
  status: ComplianceStatus;
  gap: number;
  risks: RiskRow[];
  implementedControls: number;
}) {
  if (row.status === "compliant") return "Current tier target-д хүрсэн.";
  if (row.status === "non_compliant") {
    const topRisk = row.risks[0];
    if (topRisk && riskRank(topRisk.residual_risk_level ?? topRisk.risk_level) >= 3) {
      return `${topRisk.risk_level} эрсдэл холбогдсон.`;
    }
    return `Target tier-д хүрэхэд ${row.gap} tier-ийн gap байна.`;
  }
  if (row.status === "partial") {
    return `${row.implementedControls} implemented control нотолгоо байна.`;
  }
  return "Assessment, control эсвэл asset evidence бүртгэгдээгүй.";
}

function recommendedAction(input: {
  assessment: AssessmentRow | undefined;
  derived: DerivedSignal | undefined;
  controls: ControlRow[];
  risks: RiskRow[];
  categoryCode: string;
  code: string;
}) {
  if (input.derived?.action) return input.derived.action;
  const openControl = input.controls.find(
    (control) => !controlImplemented(control.control_status),
  );
  if (openControl) {
    return `${openControl.control_id} - ${openControl.control_name} хяналтыг хэрэгжүүлж evidence бүрдүүлнэ.`;
  }
  const topRisk = input.risks[0];
  if (topRisk) {
    return `${topRisk.risk_code ?? "Эрсдэл"} бичлэгийн residual risk-г бууруулах control, owner, due date тодорхойлно.`;
  }
  if (input.assessment?.control_links) {
    return `${input.assessment.control_links} control холбоосуудын хэрэгжилтийг шалгаж gap хаана.`;
  }
  return `${input.code} subcategory дээр current/target tier assessment хийж, ${input.categoryCode} category-ийн control coverage-г баталгаажуулна.`;
}

async function mergeComplianceRows(input: {
  assessmentRows: AssessmentRow[];
  controls: ControlRow[];
  risks: RiskRow[];
  derived: Map<string, DerivedSignal>;
}) {
  const assessments = new Map(
    input.assessmentRows.map((row) => [row.subcategory_id, row]),
  );

  return (await flattenSubcategories()).map<ComplianceRow>((sub) => {
    const assessment = assessments.get(sub.code);
    const derived = input.derived.get(sub.code);
    const controls = controlsForSubcategory(
      input.controls,
      sub.code,
      sub.category_code,
    );
    const risks = risksForSubcategory(input.risks, sub.code, sub.category_code);
    const implementedControls = controls.filter((control) =>
      controlImplemented(control.control_status),
    ).length;

    const currentTier =
      assessment?.current_tier ?? derived?.current_tier ?? null;
    const targetTier = assessment?.target_tier ?? derived?.target_tier ?? null;
    const gap =
      currentTier !== null && targetTier !== null
        ? Math.max(0, targetTier - currentTier)
        : Math.max(0, assessment?.gap ?? 0);
    const nistFunction = normalizeNistFunction(
      assessment?.function_code ?? sub.function_code,
      assessment?.nist_function ?? sub.nist_function,
    );
    const status = determineStatus({
      currentTier,
      targetTier,
      hasAssessment: Boolean(assessment),
      implementedControls,
      risks,
      gap,
      hasDerived: Boolean(derived),
    });
    const evidence = [
      assessment
        ? `Импорт assessment: current ${assessment.current_tier ?? "—"} / target ${assessment.target_tier ?? "—"}.`
        : null,
      derived?.evidence ?? null,
      controls.length > 0
        ? `${implementedControls}/${controls.length} NIST control implemented.`
        : null,
      risks.length > 0 ? `${risks.length} risk register бичлэг холбогдсон.` : null,
    ].filter(Boolean) as string[];

    return {
      subcategory_id: sub.code,
      title: assessment?.category_name ?? sub.title,
      outcome: assessment?.outcome_description ?? sub.outcome,
      nist_function: nistFunction,
      function_code: assessment?.function_code ?? sub.function_code,
      category_code: assessment?.category_code ?? sub.category_code,
      category_name:
        assessment?.category_name ?? CATEGORY_NAMES[sub.category_code] ?? sub.category_code,
      status,
      status_reason: statusReason({
        status,
        gap,
        risks,
        implementedControls,
      }),
      current_tier: currentTier,
      target_tier: targetTier,
      gap,
      source: assessment
        ? "Импорт assessment"
        : derived
          ? sourceLabel(derived.source)
          : controls.length > 0 || risks.length > 0
            ? "Risk/control coverage"
            : "Not assessed",
      evidence,
      owner: assessment?.primary_owner ?? derived?.owner ?? risks[0]?.risk_owner ?? null,
      target_date: assessment?.target_date ?? null,
      risk_score:
        assessment?.risk_score ??
        (risks[0] ? Number(risks[0].residual_risk_score ?? risks[0].risk_score ?? 0) : null),
      risk_level:
        assessment?.risk_level ??
        risks[0]?.residual_risk_level ??
        risks[0]?.risk_level ??
        null,
      implemented_controls: implementedControls,
      recommended_controls: controls.length,
      controls: controls.map((control) => ({
        control_id: control.control_id,
        control_name: control.control_name,
        status: control.control_status,
        implemented: controlImplemented(control.control_status),
        tools: control.primary_tools,
        owner: control.control_owner_role,
      })),
      risks,
      affected_assets: [
        ...(derived?.affected_assets ?? []),
        ...risks
          .map((risk) => risk.asset_name)
          .filter((name): name is string => Boolean(name)),
      ].filter((value, index, list) => list.indexOf(value) === index),
      recommended_action: recommendedAction({
        assessment,
        derived,
        controls,
        risks,
        categoryCode: sub.category_code,
        code: sub.code,
      }),
    };
  });
}

function sourceLabel(source: DerivedSignal["source"]) {
  switch (source) {
    case "organization":
      return "Байгууллагын profile";
    case "assets":
      return "Asset posture";
    case "risk_controls":
      return "Risk/control coverage";
    default:
      return "Profile + asset posture";
  }
}

function summarize(rows: ComplianceRow[]) {
  const assessed = rows.filter((row) => row.status !== "not_assessed").length;
  const compliant = rows.filter((row) => row.status === "compliant").length;
  const partial = rows.filter((row) => row.status === "partial").length;
  const nonCompliant = rows.filter((row) => row.status === "non_compliant").length;
  const notAssessed = rows.length - assessed;
  const complianceRate = assessed > 0 ? Math.round((compliant / assessed) * 100) : 0;

  const byFunction = FUNCTION_ORDER.map((fn) => {
    const functionRows = rows.filter((row) => row.nist_function === fn);
    const functionAssessed = functionRows.filter(
      (row) => row.status !== "not_assessed",
    ).length;
    const functionCompliant = functionRows.filter(
      (row) => row.status === "compliant",
    ).length;

    return {
      nist_function: fn,
      total: functionRows.length,
      assessed: functionAssessed,
      compliant: functionCompliant,
      partial: functionRows.filter((row) => row.status === "partial").length,
      non_compliant: functionRows.filter((row) => row.status === "non_compliant").length,
      not_assessed: functionRows.filter((row) => row.status === "not_assessed").length,
      compliance_rate:
        functionAssessed > 0 ? Math.round((functionCompliant / functionAssessed) * 100) : 0,
    };
  });

  const gapAnalysis = rows
    .filter((row) => row.status === "non_compliant")
    .sort(
      (a, b) =>
        riskRank(b.risk_level) - riskRank(a.risk_level) ||
        b.gap - a.gap ||
        Number(b.risk_score ?? 0) - Number(a.risk_score ?? 0),
    )
    .map((row) => ({
      subcategory_id: row.subcategory_id,
      nist_function: row.nist_function,
      category_code: row.category_code,
      outcome: row.outcome,
      current_tier: row.current_tier,
      target_tier: row.target_tier,
      gap: row.gap,
      risk_level: row.risk_level,
      risk_score: row.risk_score,
      reason: row.status_reason,
      owner: row.owner,
      affected_assets: row.affected_assets.slice(0, 5),
      top_risks: row.risks.slice(0, 3).map((risk) => ({
        risk_register_id: risk.risk_register_id,
        risk_code: risk.risk_code,
        risk_title: risk.risk_title,
        risk_level: risk.risk_level,
        risk_score: risk.risk_score,
        asset_name: risk.asset_name,
      })),
      recommended_action: row.recommended_action,
    }));

  return {
    summary: {
      total_subcategories: rows.length,
      assessed,
      compliant,
      partial,
      non_compliant: nonCompliant,
      not_assessed: notAssessed,
      compliance_rate: complianceRate,
      gap_count: gapAnalysis.length,
    },
    byFunction,
    gapAnalysis,
  };
}

export async function GET() {
  try {
    const [organization, assets, assessmentRows, controls, risks, policies] =
      await Promise.all([
        getOrganization(),
        getAssets(),
        getAssessmentRows(),
        getControls(),
        getRisks(),
        getPolicySummary(),
      ]);

    const derived = deriveSignals(organization, assets, policies, risks);
    const rows = await mergeComplianceRows({
      assessmentRows,
      controls,
      risks,
      derived: derived.signals,
    });
    const result = summarize(rows);

    return NextResponse.json({
      success: true,
      generated_at: new Date().toISOString(),
      organization: organization
        ? {
            organization_name: organization.organization_name ?? null,
            industry: organization.industry ?? null,
            size_category: organization.size_category ?? null,
            risk_appetite: organization.risk_appetite ?? null,
            uses_sensitive_data: Boolean(organization.uses_sensitive_data),
          }
        : null,
      asset_scope: derived.scope,
      policy_summary: policies,
      summary: result.summary,
      by_function: result.byFunction,
      gap_analysis: result.gapAnalysis,
      rows,
    });
  } catch (error) {
    console.error("nist-csf-compliance error:", error);
    return NextResponse.json(
      {
        error:
          error instanceof Error
            ? error.message
            : "NIST CSF compliance analysis failed",
      },
      { status: 500 },
    );
  }
}
