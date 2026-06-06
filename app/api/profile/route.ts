import { pool } from "@/lib/db";
import { NextRequest, NextResponse } from "next/server";

export const revalidate = 120; // Cache for 2 minutes

const SELECT_COLUMNS = `id, organization_name, industry, size_category,
  description, risk_appetite, review_cadence_days,
  risk_tolerance_thresholds, compliance_requirements,
  critical_business_services, risk_owner, security_owner,
  risk_acceptance_approver, review_triggers,
  sensitive_data_answers, uses_sensitive_data, sensitive_asset_count,
  risk_appetite_reason, inferred_data_classification,
  availability_impact_level, it_dependency_level,
  created_at, updated_at`;

type SensitiveDataAnswers = {
  customerData: string[];
  customerSensitiveData: string[];
  internalSensitiveData: string[];
  operationalSystems: string[];
  regulatoryExposure: string[];
  cloudServices: string[];
  securityCapabilities: string[];
  dataVolume: string;
  internetExposure: string;
  availabilityImpact: string;
  itDependency: string;
  thirdPartyDependency: string;
};

const NONE_VALUE = "none";

const RISK_APPETITE_LABELS = {
  veryConservative: "Эрсдэлийг хүлээж авах түвшин маш бага",
  conservative: "Эрсдэлийг хүлээж авах түвшин бага",
  moderate: "Эрсдэлийг хүлээж авах түвшин дунд зэрэг",
  aggressive: "Эрсдэлийг хүлээж авах түвшин өндөр",
  veryAggressive: "Эрсдэлийг хүлээж авах түвшин маш өндөр",
} as const;

function normalizeStringArray(value: unknown) {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => String(item).trim())
    .filter((item) => item.length > 0);
}

function normalizeSensitiveDataAnswers(value: unknown): SensitiveDataAnswers {
  const source =
    value && typeof value === "object"
      ? (value as Partial<Record<keyof SensitiveDataAnswers, unknown>>)
      : {};

  return {
    customerData: normalizeStringArray(source.customerData),
    customerSensitiveData: normalizeStringArray(source.customerSensitiveData),
    internalSensitiveData: normalizeStringArray(source.internalSensitiveData),
    operationalSystems: normalizeStringArray(source.operationalSystems),
    regulatoryExposure: normalizeStringArray(source.regulatoryExposure),
    cloudServices: normalizeStringArray(source.cloudServices),
    securityCapabilities: normalizeStringArray(source.securityCapabilities),
    dataVolume: String(source.dataVolume ?? ""),
    internetExposure: String(source.internetExposure ?? ""),
    availabilityImpact: String(source.availabilityImpact ?? ""),
    itDependency: String(source.itDependency ?? ""),
    thirdPartyDependency: String(source.thirdPartyDependency ?? ""),
  };
}

function hasSelectedValues(values: string[]) {
  return values.some((value) => value !== NONE_VALUE);
}

function deriveDataClassification(answers: SensitiveDataAnswers) {
  const hasCustomerData = hasSelectedValues(answers.customerData);
  const hasCustomerSensitiveData = hasSelectedValues(
    answers.customerSensitiveData,
  );
  const hasInternalSensitiveData = hasSelectedValues(
    answers.internalSensitiveData,
  );
  const hasRestrictedInternalData = answers.internalSensitiveData.some(
    (value) => ["payroll", "strategy"].includes(value),
  );

  if (hasRestrictedInternalData) return "Restricted";
  if (hasCustomerSensitiveData) return "Confidential";
  if (hasCustomerData || hasInternalSensitiveData) return "Internal";

  return "Public";
}

function getControlMaturityBaseline(capabilities: string[]) {
  const selectedCapabilities = capabilities.filter(
    (capability) => capability !== NONE_VALUE,
  );

  if (selectedCapabilities.length === 0) return "No baseline";
  if (selectedCapabilities.length <= 2) return "Basic";
  if (selectedCapabilities.length <= 4) return "Developing";

  return "Established";
}

function getQuestionnaireSensitivityWeight(answers: SensitiveDataAnswers) {
  const classification = deriveDataClassification(answers);
  const availabilityWeight =
    answers.availabilityImpact === "veryHigh"
      ? 1
      : answers.availabilityImpact === "high"
        ? 0.75
        : answers.availabilityImpact === "medium"
          ? 0.35
          : 0;
  const dependencyWeight =
    answers.itDependency === "veryHigh"
      ? 1
      : answers.itDependency === "high"
        ? 0.75
        : answers.itDependency === "medium"
          ? 0.35
          : 0;
  const regulatoryWeight = hasSelectedValues(answers.regulatoryExposure)
    ? 1
    : 0;
  const dataVolumeWeight =
    answers.dataVolume === "10000plus"
      ? 1.25
      : answers.dataVolume === "1000to10000"
        ? 0.75
        : answers.dataVolume === "100to1000"
          ? 0.35
          : answers.dataVolume === "under100"
            ? 0.1
            : 0;
  const exposureWeight =
    answers.internetExposure === "publicApi"
      ? 1.25
      : answers.internetExposure === "publicWeb"
        ? 0.9
        : answers.internetExposure === "vpnRequired"
          ? 0.35
          : 0;
  const thirdPartyWeight =
    answers.thirdPartyDependency === "coreDepends"
      ? 1
      : answers.thirdPartyDependency === "many"
        ? 0.75
        : answers.thirdPartyDependency === "few"
          ? 0.35
          : 0;
  const controlMaturityAdjustment =
    getControlMaturityBaseline(answers.securityCapabilities) === "Established"
      ? -0.5
      : getControlMaturityBaseline(answers.securityCapabilities) ===
          "No baseline"
        ? 0.75
        : 0;

  const dataWeight =
    classification === "Restricted"
      ? 2.5
      : classification === "Confidential"
        ? 2
        : classification === "Internal"
          ? 1
          : 0;

  return Math.max(
    0,
    dataWeight +
      availabilityWeight +
      dependencyWeight +
      regulatoryWeight +
      dataVolumeWeight +
      exposureWeight +
      thirdPartyWeight +
      controlMaturityAdjustment,
  );
}

function getOrganizationSizeWeight(sizeCategory: unknown) {
  const normalized = String(sizeCategory ?? "").toLowerCase();

  if (normalized.includes("дунд") || normalized.includes("251")) return 2;
  if (normalized.includes("жижиг") || normalized.includes("51")) return 1;
  if (normalized.includes("микро") || normalized.includes("1-50")) return 0;

  return 1;
}

function hasSensitiveComplianceRequirement(complianceRequirements: unknown) {
  const sensitiveRequirementTerms = [
    "gdpr",
    "hipaa",
    "pci",
    "data protection",
    "privacy",
    "personal data",
    "мэдээлэл хамгаалах",
    "хувийн мэдээлэл",
    "нууцлал",
  ];

  return normalizeStringArray(complianceRequirements).some((item) => {
    const normalized = item.toLowerCase();
    return sensitiveRequirementTerms.some((term) => normalized.includes(term));
  });
}

async function getSensitiveDataSignal() {
  const tableResult = await pool.query(
    "SELECT to_regclass('public.assets') AS table_name",
  );

  if (!tableResult.rows[0]?.table_name) {
    return {
      usesSensitiveData: false,
      sensitiveAssetCount: 0,
      restrictedAssetCount: 0,
    };
  }

  const columnResult = await pool.query(`
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'assets'
      AND column_name = 'data_classification'
    LIMIT 1
  `);

  if (columnResult.rows.length === 0) {
    return {
      usesSensitiveData: false,
      sensitiveAssetCount: 0,
      restrictedAssetCount: 0,
    };
  }

  const result = await pool.query(`
    SELECT
      COUNT(*) FILTER (
        WHERE lower(coalesce(data_classification, '')) IN ('confidential', 'restricted')
      )::int AS sensitive_asset_count,
      COUNT(*) FILTER (
        WHERE lower(coalesce(data_classification, '')) = 'restricted'
      )::int AS restricted_asset_count
    FROM assets
  `);

  const sensitiveAssetCount = Number(
    result.rows[0]?.sensitive_asset_count ?? 0,
  );
  const restrictedAssetCount = Number(
    result.rows[0]?.restricted_asset_count ?? 0,
  );

  return {
    usesSensitiveData: sensitiveAssetCount > 0,
    sensitiveAssetCount,
    restrictedAssetCount,
  };
}

function calculateRiskAppetite(
  sizeCategory: unknown,
  complianceRequirements: unknown,
  sensitiveDataSignal: Awaited<ReturnType<typeof getSensitiveDataSignal>>,
  sensitiveDataAnswers: unknown,
) {
  const sizeWeight = getOrganizationSizeWeight(sizeCategory);
  const answers = normalizeSensitiveDataAnswers(sensitiveDataAnswers);
  const complianceSensitive = hasSensitiveComplianceRequirement(
    complianceRequirements,
  );
  const sensitiveDataWeight = Math.max(
    getQuestionnaireSensitivityWeight(answers),
    sensitiveDataSignal.restrictedAssetCount > 0
      ? 2
      : sensitiveDataSignal.usesSensitiveData
        ? 1.5
        : complianceSensitive
          ? 1
          : 0,
  );
  const riskSensitivityScore = sizeWeight + sensitiveDataWeight;

  if (riskSensitivityScore >= 3.5) {
    return RISK_APPETITE_LABELS.veryConservative;
  }

  if (riskSensitivityScore >= 2.5) {
    return RISK_APPETITE_LABELS.conservative;
  }

  if (riskSensitivityScore >= 1.5) {
    return RISK_APPETITE_LABELS.moderate;
  }

  if (riskSensitivityScore >= 0.5) {
    return RISK_APPETITE_LABELS.aggressive;
  }

  return RISK_APPETITE_LABELS.veryAggressive;
}

async function enrichOrganizationProfile<T extends Record<string, unknown>>(
  organization: T,
) {
  const sensitiveDataSignal = await getSensitiveDataSignal();
  const answers = normalizeSensitiveDataAnswers(
    organization.sensitive_data_answers,
  );
  const inferredDataClassification = deriveDataClassification(answers);
  const questionnaireUsesSensitiveData =
    inferredDataClassification !== "Public";
  const riskAppetite = calculateRiskAppetite(
    organization.size_category,
    organization.compliance_requirements,
    sensitiveDataSignal,
    answers,
  );

  return {
    ...organization,
    sensitive_data_answers: answers,
    risk_appetite: riskAppetite,
    uses_sensitive_data:
      questionnaireUsesSensitiveData || sensitiveDataSignal.usesSensitiveData,
    sensitive_asset_count: sensitiveDataSignal.sensitiveAssetCount,
    inferred_data_classification: inferredDataClassification,
    availability_impact_level: answers.availabilityImpact,
    it_dependency_level: answers.itDependency,
    risk_appetite_reason: sensitiveDataSignal.usesSensitiveData
      ? `Байгууллагын хэмжээ болон эмзэг мэдээлэлтэй ${sensitiveDataSignal.sensitiveAssetCount} хөрөнгөнөөс тооцоолов.`
      : questionnaireUsesSensitiveData
        ? "Sensitive Data Identification асуулгын хариулт, data volume, exposure, control maturity, SaaS dependency болон байгууллагын хэмжээнээс тооцоолов."
        : "Байгууллагын хэмжээ болон сонгосон шаардлагуудаас тооцоолов.",
  };
}

async function ensureOrganizationProfileSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS organization_information (
      id SERIAL PRIMARY KEY,
      organization_name VARCHAR(255) NOT NULL,
      industry VARCHAR(100) NOT NULL,
      size_category VARCHAR(100) NOT NULL,
      description TEXT,
      risk_appetite VARCHAR(255),
      review_cadence_days INTEGER DEFAULT 90,
      risk_tolerance_thresholds JSONB,
      compliance_requirements JSONB DEFAULT '[]'::jsonb,
      critical_business_services TEXT,
      risk_owner VARCHAR(255),
      security_owner VARCHAR(255),
      risk_acceptance_approver VARCHAR(255),
      review_triggers JSONB DEFAULT '[]'::jsonb,
      sensitive_data_answers JSONB DEFAULT '{}'::jsonb,
      uses_sensitive_data BOOLEAN DEFAULT FALSE,
      sensitive_asset_count INTEGER DEFAULT 0,
      risk_appetite_reason TEXT,
      inferred_data_classification VARCHAR(50),
      availability_impact_level VARCHAR(50),
      it_dependency_level VARCHAR(50),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(
    `ALTER TABLE organization_information ADD COLUMN IF NOT EXISTS compliance_requirements JSONB DEFAULT '[]'::jsonb`,
  );
  await pool.query(
    `ALTER TABLE organization_information ADD COLUMN IF NOT EXISTS critical_business_services TEXT`,
  );
  await pool.query(
    `ALTER TABLE organization_information ADD COLUMN IF NOT EXISTS risk_owner VARCHAR(255)`,
  );
  await pool.query(
    `ALTER TABLE organization_information ADD COLUMN IF NOT EXISTS security_owner VARCHAR(255)`,
  );
  await pool.query(
    `ALTER TABLE organization_information ADD COLUMN IF NOT EXISTS risk_acceptance_approver VARCHAR(255)`,
  );
  await pool.query(
    `ALTER TABLE organization_information ADD COLUMN IF NOT EXISTS review_triggers JSONB DEFAULT '[]'::jsonb`,
  );
  await pool.query(
    `ALTER TABLE organization_information ADD COLUMN IF NOT EXISTS risk_tolerance_thresholds JSONB`,
  );
  await pool.query(
    `ALTER TABLE organization_information ADD COLUMN IF NOT EXISTS review_cadence_days INTEGER DEFAULT 90`,
  );
  await pool.query(
    `ALTER TABLE organization_information ADD COLUMN IF NOT EXISTS sensitive_data_answers JSONB DEFAULT '{}'::jsonb`,
  );
  await pool.query(
    `ALTER TABLE organization_information ADD COLUMN IF NOT EXISTS uses_sensitive_data BOOLEAN DEFAULT FALSE`,
  );
  await pool.query(
    `ALTER TABLE organization_information ADD COLUMN IF NOT EXISTS sensitive_asset_count INTEGER DEFAULT 0`,
  );
  await pool.query(
    `ALTER TABLE organization_information ADD COLUMN IF NOT EXISTS risk_appetite_reason TEXT`,
  );
  await pool.query(
    `ALTER TABLE organization_information ADD COLUMN IF NOT EXISTS inferred_data_classification VARCHAR(50)`,
  );
  await pool.query(
    `ALTER TABLE organization_information ADD COLUMN IF NOT EXISTS availability_impact_level VARCHAR(50)`,
  );
  await pool.query(
    `ALTER TABLE organization_information ADD COLUMN IF NOT EXISTS it_dependency_level VARCHAR(50)`,
  );
}

function toJsonArray(value: unknown) {
  return Array.isArray(value)
    ? JSON.stringify(
        value
          .map((item) => String(item).trim())
          .filter((item) => item.length > 0),
      )
    : JSON.stringify([]);
}

export async function GET() {
  try {
    await ensureOrganizationProfileSchema();

    const result = await pool.query(
      `SELECT ${SELECT_COLUMNS}
        FROM organization_information
        LIMIT 1`,
    );

    if (result.rows.length === 0) {
      return NextResponse.json(
        { organization: null, message: "Байгууллагын мэдээлэл олдсонгүй" },
        { status: 200 },
      );
    }

    const organization = await enrichOrganizationProfile(result.rows[0]);
    const response = NextResponse.json({ organization }, { status: 200 });

    response.headers.set(
      "Cache-Control",
      "public, s-maxage=120, stale-while-revalidate=240",
    );

    return response;
  } catch (error) {
    console.error("Fetch profile error:", error);
    const errorMessage =
      error instanceof Error ? error.message : "Серверийн дотоод алдаа";
    return NextResponse.json({ message: errorMessage }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const {
      organization_name,
      industry,
      size_category,
      description,
      review_cadence_days,
      risk_tolerance_thresholds,
      compliance_requirements,
      critical_business_services,
      risk_owner,
      security_owner,
      risk_acceptance_approver,
      review_triggers,
      sensitive_data_answers,
    } = await req.json();

    await ensureOrganizationProfileSchema();

    if (!organization_name || !industry || !size_category) {
      return NextResponse.json(
        {
          message: "Байгууллагын нэр, салбар, байгууллагын хэмжээ шаардлагатай",
        },
        { status: 400 },
      );
    }

    const thresholdsJson =
      risk_tolerance_thresholds && typeof risk_tolerance_thresholds === "object"
        ? JSON.stringify(risk_tolerance_thresholds)
        : null;
    const complianceJson = toJsonArray(compliance_requirements);
    const reviewTriggersJson = toJsonArray(review_triggers);
    const normalizedSensitiveDataAnswers = normalizeSensitiveDataAnswers(
      sensitive_data_answers,
    );
    const sensitiveDataAnswersJson = JSON.stringify(
      normalizedSensitiveDataAnswers,
    );
    const inferredDataClassification = deriveDataClassification(
      normalizedSensitiveDataAnswers,
    );
    const questionnaireUsesSensitiveData =
      inferredDataClassification !== "Public";
    const sensitiveDataSignal = await getSensitiveDataSignal();
    const calculatedRiskAppetite = calculateRiskAppetite(
      size_category,
      compliance_requirements,
      sensitiveDataSignal,
      normalizedSensitiveDataAnswers,
    );
    const riskAppetiteReason = sensitiveDataSignal.usesSensitiveData
      ? `Байгууллагын хэмжээ болон эмзэг мэдээлэлтэй ${sensitiveDataSignal.sensitiveAssetCount} хөрөнгөнөөс тооцоолов.`
      : questionnaireUsesSensitiveData
        ? "Sensitive Data Identification асуулгын хариулт, data volume, exposure, control maturity, SaaS dependency болон байгууллагын хэмжээнээс тооцоолов."
        : "Байгууллагын хэмжээ болон сонгосон шаардлагуудаас тооцоолов.";

    const checkResult = await pool.query(
      "SELECT id FROM organization_information LIMIT 1",
    );

    if (checkResult.rows.length > 0) {
      const result = await pool.query(
        `UPDATE organization_information
          SET organization_name = $1,
              industry = $2,
              size_category = $3,
              description = $4,
              risk_appetite = $5,
              review_cadence_days = $6,
              risk_tolerance_thresholds = $7::jsonb,
                compliance_requirements = $8::jsonb,
                critical_business_services = $9,
                risk_owner = $10,
                security_owner = $11,
                risk_acceptance_approver = $12,
                review_triggers = $13::jsonb,
                sensitive_data_answers = $14::jsonb,
                uses_sensitive_data = $15,
                sensitive_asset_count = $16,
                risk_appetite_reason = $17,
                inferred_data_classification = $18,
                availability_impact_level = $19,
                it_dependency_level = $20,
              updated_at = CURRENT_TIMESTAMP
              WHERE id = $21
          RETURNING ${SELECT_COLUMNS}`,
        [
          organization_name,
          industry,
          size_category,
          description,
          calculatedRiskAppetite,
          review_cadence_days,
          thresholdsJson,
          complianceJson,
          critical_business_services,
          risk_owner,
          security_owner,
          risk_acceptance_approver,
          reviewTriggersJson,
          sensitiveDataAnswersJson,
          questionnaireUsesSensitiveData ||
            sensitiveDataSignal.usesSensitiveData,
          sensitiveDataSignal.sensitiveAssetCount,
          riskAppetiteReason,
          inferredDataClassification,
          normalizedSensitiveDataAnswers.availabilityImpact,
          normalizedSensitiveDataAnswers.itDependency,
          checkResult.rows[0].id,
        ],
      );

      return NextResponse.json(
        {
          message: "Байгууллагын мэдээлэл амжилттай шинэчлэгдлээ",
          organization: await enrichOrganizationProfile(result.rows[0]),
        },
        { status: 200 },
      );
    } else {
      const result = await pool.query(
        `INSERT INTO organization_information
          (organization_name, industry, size_category, description,
            risk_appetite, review_cadence_days,
            risk_tolerance_thresholds, compliance_requirements,
            critical_business_services, risk_owner, security_owner,
            risk_acceptance_approver, review_triggers,
            sensitive_data_answers, uses_sensitive_data, sensitive_asset_count,
            risk_appetite_reason, inferred_data_classification,
            availability_impact_level, it_dependency_level)
            VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10, $11, $12, $13::jsonb, $14::jsonb, $15, $16, $17, $18, $19, $20)
          RETURNING ${SELECT_COLUMNS}`,
        [
          organization_name,
          industry,
          size_category,
          description,
          calculatedRiskAppetite,
          review_cadence_days,
          thresholdsJson,
          complianceJson,
          critical_business_services,
          risk_owner,
          security_owner,
          risk_acceptance_approver,
          reviewTriggersJson,
          sensitiveDataAnswersJson,
          questionnaireUsesSensitiveData ||
            sensitiveDataSignal.usesSensitiveData,
          sensitiveDataSignal.sensitiveAssetCount,
          riskAppetiteReason,
          inferredDataClassification,
          normalizedSensitiveDataAnswers.availabilityImpact,
          normalizedSensitiveDataAnswers.itDependency,
        ],
      );

      return NextResponse.json(
        {
          message: "Байгууллагын мэдээлэл амжилттай үүслээ",
          organization: await enrichOrganizationProfile(result.rows[0]),
        },
        { status: 201 },
      );
    }
  } catch (error) {
    console.error("Save profile error:", error);
    const errorMessage =
      error instanceof Error ? error.message : "Серверийн дотоод алдаа";
    return NextResponse.json({ message: errorMessage }, { status: 500 });
  }
}
