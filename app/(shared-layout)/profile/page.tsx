"use client";

import { useAuth } from "@/app/context/AuthContext";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Building2,
  CalendarClock,
  Check,
  CheckCircle2,
  FileText,
  Gauge,
  Landmark,
  ListChecks,
  Pencil,
  Plus,
  Scale,
  Trash2,
  UserCheck,
  Users,
  X,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

interface OrganizationData {
  id?: string;
  organization_name: string;
  industry: string;
  size_category: string;
  description?: string;
  risk_appetite?: string;
  uses_sensitive_data?: boolean;
  sensitive_asset_count?: number;
  risk_appetite_reason?: string;
  review_cadence_days?: number;
  risk_tolerance_thresholds?: {
    low?: number;
    medium?: number;
    high?: number;
    critical?: number;
  };
  compliance_requirements?: string[];
  critical_business_services?: string;
  risk_owner?: string;
  security_owner?: string;
  risk_acceptance_approver?: string;
  review_triggers?: string[];
  sensitive_data_answers?: SensitiveDataAnswers;
  inferred_data_classification?: string;
  availability_impact_level?: string;
  it_dependency_level?: string;
  created_at?: string;
  updated_at?: string;
}

interface CriticalBusinessProcess {
  id: number;
  process_code?: string | null;
  process_name: string;
  criticality?: string | null;
  status?: string | null;
  asset_count?: number;
  risk_count?: number;
  highest_risk_score?: number | string | null;
  highest_risk_level?: string | null;
  avg_risk_score?: number | string | null;
  linked_risks?: LinkedProcessRisk[];
}

interface LinkedProcessRisk {
  risk_register_id: number;
  risk_code?: string | null;
  risk_title: string;
  asset_name?: string | null;
  risk_score?: number | string | null;
  risk_level?: string | null;
  residual_risk_score?: number | string | null;
  residual_risk_level?: string | null;
  status?: string | null;
}

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

type SensitiveMultiSelectKey =
  | "customerData"
  | "customerSensitiveData"
  | "internalSensitiveData"
  | "operationalSystems"
  | "regulatoryExposure"
  | "cloudServices"
  | "securityCapabilities";

type SensitiveSingleSelectKey =
  | "dataVolume"
  | "internetExposure"
  | "availabilityImpact"
  | "itDependency"
  | "thirdPartyDependency";

const INDUSTRY_OPTIONS = [
  "Эрүүл мэнд",
  "Банк, санхүү",
  "Технологи",
  "Үйлдвэрлэл",
  "Худалдаа",
  "Засгийн газар",
  "Боловсрол",
  "Эрчим хүч",
  "Харилцаа холбоо",
  "Тээвэр",
  "Бусад",
];

const SIZE_CATEGORIES = [
  "Микро (1-50 ажилтан)",
  "Жижиг (51-250 ажилтан)",
  "Дунд (251-1000 ажилтан)",
];

const RISK_APPETITE_LABELS = {
  veryConservative: "Маш бага",
  conservative: "Бага",
  moderate: "Дундаж",
  aggressive: "Өндөр",
  veryAggressive: "Маш өндөр",
} as const;

const REVIEW_CADENCE_OPTIONS = [
  { value: 30, label: "Сар бүр (30 хоног) - Маш чухал хөрөнгө" },
  { value: 90, label: "Улирал бүр (90 хоног) - Өндөр эрсдэлтэй хөрөнгө" },
  { value: 180, label: "Хагас жил тутам (180 хоног)" },
  { value: 365, label: "Жил бүр (365 хоног)" },
];

const COMPLIANCE_OPTIONS = [
  { value: "NIST CSF 2.0", label: "NIST CSF 2.0" },
  { value: "ISO 27001", label: "ISO 27001" },
  { value: "SOC 2", label: "SOC 2" },
  { value: "PCI DSS", label: "PCI DSS" },
  { value: "HIPAA", label: "HIPAA" },
  { value: "GDPR", label: "GDPR" },
  {
    value: "Mongolian data protection requirements",
    label: "Монгол Улсын мэдээлэл хамгааллын хууль, журам",
  },
  {
    value: "Internal security policy",
    label: "Дотоод аюулгүй байдлын бодлого",
  },
];

const REVIEW_TRIGGER_OPTIONS = [
  { value: "After security incident", label: "Аюулгүй байдлын осолын дараа" },
  {
    value: "After infrastructure change",
    label: "Дэд бүтцийн өөрчлөлтийн дараа",
  },
  {
    value: "After new critical vulnerability",
    label: "Шинэ ноцтой эмзэг байдал илэрсний дараа",
  },
  {
    value: "After cloud or SaaS onboarding",
    label: "Үүлэн эсвэл SaaS үйлчилгээ нэвтрүүлсний дараа",
  },
  {
    value: "After major vendor change",
    label: "Гол ханган нийлүүлэгч өөрчлөгдсөний дараа",
  },
  {
    value: "Quarterly scheduled review",
    label: "Улирал бүрийн төлөвлөгөөт хяналт",
  },
];

const THRESHOLD_FIELDS = [
  { key: "low", label: "Бага", fallback: 4 },
  { key: "medium", label: "Дунд", fallback: 9 },
  { key: "high", label: "Өндөр", fallback: 16 },
  { key: "critical", label: "Ноцтой", fallback: 25 },
] as const;

const NONE_VALUE = "none";

const SENSITIVE_DATA_DEFAULT_ANSWERS: SensitiveDataAnswers = {
  customerData: [],
  customerSensitiveData: [],
  internalSensitiveData: [],
  operationalSystems: [],
  regulatoryExposure: [],
  cloudServices: [],
  securityCapabilities: [],
  dataVolume: "",
  internetExposure: "",
  availabilityImpact: "",
  itDependency: "",
  thirdPartyDependency: "",
};

const SENSITIVE_DATA_MULTI_QUESTIONS: Array<{
  key: SensitiveMultiSelectKey;
  question: string;
  options: Array<{ value: string; label: string }>;
}> = [
  {
    key: "customerData",
    question:
      "Танай байгууллага хэрэглэгчийн дараах төрлийн мэдээллийг хадгалдаг уу?",
    options: [
      { value: "name", label: "Нэр" },
      { value: "phone", label: "Утасны дугаар" },
      { value: "email", label: "И-мэйл" },
      { value: "nationalId", label: "Регистрийн дугаар" },
      { value: "address", label: "Хаяг" },
      { value: NONE_VALUE, label: "Аль нь ч байхгүй" },
    ],
  },
  {
    key: "customerSensitiveData",
    question:
      "Танай байгууллага хэрэглэгчийн дараах эмзэг мэдээллийг хадгалдаг уу?",
    options: [
      { value: "financial", label: "Санхүүгийн мэдээлэл" },
      { value: "paymentCard", label: "Төлбөрийн картын мэдээлэл" },
      { value: "health", label: "Эрүүл мэндийн мэдээлэл" },
      { value: "identityDocument", label: "Иргэний үнэмлэх / паспорт" },
      { value: "biometric", label: "Биометр мэдээлэл" },
      { value: NONE_VALUE, label: "Аль нь ч байхгүй" },
    ],
  },
  {
    key: "internalSensitiveData",
    question: "Танай байгууллага дараах дотоод мэдээллийг хадгалдаг уу?",
    options: [
      { value: "financialReport", label: "Санхүүгийн тайлан" },
      { value: "payroll", label: "Цалингийн мэдээлэл" },
      { value: "contracts", label: "Гэрээний мэдээлэл" },
      { value: "strategy", label: "Судалгаа / стратегийн баримт бичиг" },
      { value: NONE_VALUE, label: "Аль нь ч байхгүй" },
    ],
  },
  {
    key: "operationalSystems",
    question: "Доорх системүүдийн аль нэгийг нь ашигладаг уу?",
    options: [
      { value: "email", label: "Имэйл систем" },
      { value: "accounting", label: "Нягтлан бодох бүртгэлийн систем" },
      { value: "erp", label: "ERP систем" },
      { value: "hr", label: "Хүний нөөцийн систем" },
      { value: "crm", label: "Харилцагчийн удирдлагын систем" },
      { value: "websiteOnly", label: "Зөвхөн вэбсайт" },
      { value: "socialOnly", label: "Зөвхөн сошиал медиа" },
    ],
  },
  {
    key: "regulatoryExposure",
    question:
      "Танай байгууллага дараах хууль, дүрэм зохицуулалтын хүрээнд ажилладаг уу?",
    options: [
      {
        value: "mongoliaCybersecurityLaw",
        label: "Монгол Улсын Кибер аюулгүй байдлын тухай хууль",
      },
      {
        value: "personalDataProtectionLaw",
        label: "Хувь хүний мэдээлэл хамгаалах тухай хууль",
      },
      { value: "frc", label: "Санхүүгийн зохицуулах хорооны (FRC) шаардлага" },
      { value: "mongolBank", label: "Монгол Банкны шаардлага" },
      { value: NONE_VALUE, label: "Аль нь ч байхгүй" },
    ],
  },
  {
    key: "cloudServices",
    question: "Танай байгууллага доорх үүлэн үйлчилгээнүүдийг ашигладаг уу?",
    options: [
      { value: "googleWorkspace", label: "Google Workspace" },
      { value: "microsoft365", label: "Microsoft 365" },
      { value: "aws", label: "AWS" },
      { value: "azure", label: "Azure" },
      { value: "localOnly", label: "Local server only" },
    ],
  },
  {
    key: "securityCapabilities",
    question: "Танай байгууллагад дараах хамгаалалтын шийдлүүд байгаа юу?",
    options: [
      { value: "firewall", label: "Firewall" },
      {
        value: "endpointProtection",
        label: "Төгсгөлийн төхөөрөмжийн хамгаалалт",
      },
      { value: "backupSystem", label: "Нөөцлөлтийн систем" },
      { value: "logMonitoring", label: "Лог хяналт" },
      { value: "mfa", label: "MFA" },
      { value: NONE_VALUE, label: "Байхгүй" },
    ],
  },
];

const SENSITIVE_DATA_SINGLE_QUESTIONS: Array<{
  key: SensitiveSingleSelectKey;
  question: string;
  options: Array<{ value: string; label: string }>;
}> = [
  {
    key: "dataVolume",
    question:
      "Танай байгууллага ойролцоогоор хэдэн хэрэглэгчийн мэдээллийг хадгалдаг вэ?",
    options: [
      { value: "under100", label: "< 100" },
      { value: "100to1000", label: "100 - 1,000" },
      { value: "1000to10000", label: "1,000 - 10,000" },
      { value: "10000plus", label: "10,000+" },
    ],
  },
  {
    key: "internetExposure",
    question: "Танай системүүд рүү гадаад сүлжээнээс шууд хандах боломжтой юу?",
    options: [
      { value: "internalOnly", label: "Зөвхөн дотоод сүлжээ" },
      { value: "vpnRequired", label: "VPN шаардлагатай" },
      { value: "publicWeb", label: "Нийтэд нээлттэй вэб хандалт" },
      { value: "publicApi", label: "Нийтэд нээлттэй вэб болон API" },
    ],
  },
  {
    key: "availabilityImpact",
    question:
      "Хэрэв танай байгууллагын мэдээллийн систем 24 цаг ажиллахгүй бол ямар нөлөө үзүүлэх вэ?",
    options: [
      { value: "veryLow", label: "Маш бага" },
      { value: "medium", label: "Дунд" },
      { value: "high", label: "Өндөр" },
      { value: "veryHigh", label: "Маш өндөр" },
    ],
  },
  {
    key: "itDependency",
    question:
      "Танай байгууллагын үндсэн үйл ажиллагаа IT системээс хэр хамааралтай вэ?",
    options: [
      { value: "low", label: "Бага" },
      { value: "medium", label: "Дунд" },
      { value: "high", label: "Өндөр" },
      { value: "veryHigh", label: "Маш өндөр" },
    ],
  },
  {
    key: "thirdPartyDependency",
    question:
      "Танай байгууллага үйл ажиллагаандаа SaaS үйлчилгээ хэр ашигладаг вэ?",
    options: [
      { value: "none", label: "Ашигладаггүй" },
      { value: "few", label: "Цөөн үйлчилгээ ашигладаг" },
      { value: "many", label: "Олон үйлчилгээ ашигладаг" },
      {
        value: "coreDepends",
        label: "Үндсэн үйл ажиллагаа SaaS-аас хамаардаг",
      },
    ],
  },
];

const ORG_SELECT_CONTENT_CLASS = "profile-select-content";
const ORG_SELECT_ITEM_CLASS = "profile-select-item";
const ORG_PROFILE_CARD_CLASS = "app-card-surface";
const ORG_FORM_FIELD_CLASS = "profile-form-field";
const ORG_FORM_PANEL_CLASS = "profile-form-panel rounded-lg border p-4";
const ORG_OPTION_CLASS =
  "profile-choice-row flex items-center gap-2 rounded-md border px-3 py-2 text-sm transition-colors";
const ORG_CHOICE_INPUT_CLASS =
  "profile-choice-input h-4 w-4 shrink-0 accent-blue-600";

function formatComplianceRequirement(value: string) {
  return (
    COMPLIANCE_OPTIONS.find((option) => option.value === value)?.label ?? value
  );
}

function formatReviewTrigger(value: string) {
  return (
    REVIEW_TRIGGER_OPTIONS.find((option) => option.value === value)?.label ??
    value
  );
}

function formatBusinessProcessLabel(process: CriticalBusinessProcess) {
  return process.process_name;
}

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

function formatDataClassification(value?: string) {
  const labels: Record<string, string> = {
    Public: "Нийтийн",
    Internal: "Дотоод",
    Confidential: "Нууц",
    Restricted: "Маш нууц",
  };

  return value ? (labels[value] ?? value) : "Тодорхойгүй";
}

function getImpactLabel(value?: string) {
  return (
    SENSITIVE_DATA_SINGLE_QUESTIONS.flatMap(
      (question) => question.options,
    ).find((option) => option.value === value)?.label ?? "Тодорхойгүй"
  );
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

function formatControlMaturityBaseline(value: string) {
  const labels: Record<string, string> = {
    "No baseline": "Суурь хамгаалалт байхгүй",
    Basic: "Анхан шат",
    Developing: "Хөгжиж буй",
    Established: "Тогтворжсон",
  };

  return labels[value] ?? value;
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

function getOrganizationSizeWeight(sizeCategory: string) {
  const normalized = sizeCategory.toLowerCase();

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
  ];

  return normalizeStringArray(complianceRequirements).some((item) => {
    const normalized = item.toLowerCase();
    return sensitiveRequirementTerms.some((term) => normalized.includes(term));
  });
}

function calculateRiskAppetitePreview(data: OrganizationData) {
  const sizeWeight = getOrganizationSizeWeight(data.size_category);
  const sensitiveDataAnswers = normalizeSensitiveDataAnswers(
    data.sensitive_data_answers,
  );
  const sensitiveDataWeight = Math.max(
    getQuestionnaireSensitivityWeight(sensitiveDataAnswers),
    data.uses_sensitive_data
      ? 1.5
      : hasSensitiveComplianceRequirement(data.compliance_requirements)
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

// ─── Risk Appetite levels ─────────────────────────────────────────────────────

const APPETITE_LEVELS = [
  {
    value: RISK_APPETITE_LABELS.veryConservative,
    short: "Маш бага",
    color: "#6366f1",
    bg: "bg-indigo-500",
    lightBg: "bg-indigo-500/10",
    border: "border-indigo-500/40",
    text: "text-indigo-700 dark:text-indigo-400",
    ring: "ring-indigo-500",
  },
  {
    value: RISK_APPETITE_LABELS.conservative,
    short: "Бага",
    color: "#3b82f6",
    bg: "bg-blue-500",
    lightBg: "bg-blue-500/10",
    border: "border-blue-500/40",
    text: "text-blue-700 dark:text-blue-400",
    ring: "ring-blue-500",
  },
  {
    value: RISK_APPETITE_LABELS.moderate,
    short: "Дундаж",
    color: "#f59e0b",
    bg: "bg-amber-500",
    lightBg: "bg-amber-500/10",
    border: "border-amber-500/40",
    text: "text-amber-700 dark:text-amber-400",
    ring: "ring-amber-500",
  },
  {
    value: RISK_APPETITE_LABELS.aggressive,
    short: "Өндөр",
    color: "#f97316",
    bg: "bg-orange-500",
    lightBg: "bg-orange-500/10",
    border: "border-orange-500/40",
    text: "text-orange-700 dark:text-orange-400",
    ring: "ring-orange-500",
  },
  {
    value: RISK_APPETITE_LABELS.veryAggressive,
    short: "Маш өндөр",
    color: "#ef4444",
    bg: "bg-red-500",
    lightBg: "bg-red-500/10",
    border: "border-red-500/40",
    text: "text-red-700 dark:text-red-400",
    ring: "ring-red-500",
  },
];

function RiskAppetiteHero({ appetiteLabel }: { appetiteLabel: string }) {
  const activeIdx = APPETITE_LEVELS.findIndex((l) => l.value === appetiteLabel);
  const active =
    activeIdx >= 0 ? APPETITE_LEVELS[activeIdx] : APPETITE_LEVELS[2];
  const idx = activeIdx >= 0 ? activeIdx : 2;

  return (
    <div
      className={`rounded-xl border-2 ${active.border} ${active.lightBg} p-6`}
    >
      {/* Top row */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
        <div className="flex items-center gap-3">
          <div
            className={`p-2.5 rounded-xl ${active.lightBg} border ${active.border}`}
          >
            <Gauge className={`h-6 w-6 ${active.text}`} />
          </div>
          <div>
            <p className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
              Эрсдэлийг хүлээж авах хэмжээ
            </p>
            <h2
              className={`text-2xl font-black tracking-tight mt-0.5 ${active.text}`}
            >
              {active.short}
            </h2>
          </div>
        </div>
      </div>

      {/* Spectrum bar */}
      <div className="space-y-3">
        <div className="grid grid-cols-5 gap-1.5">
          {APPETITE_LEVELS.map((level, i) => (
            <div
              key={level.short}
              className="flex flex-col items-center gap-1.5"
            >
              <div
                className={`w-full h-3 rounded-full transition-all ${
                  i === idx
                    ? `${level.bg} shadow-md`
                    : i < idx
                      ? `${level.bg} opacity-30`
                      : "bg-muted"
                }`}
              />
              {i === idx && (
                <div
                  className="w-2.5 h-2.5 rounded-full ring-2 ring-offset-2 ring-offset-background"
                  style={{
                    backgroundColor: level.color,
                    ["--tw-ring-color" as string]: level.color,
                  }}
                />
              )}
            </div>
          ))}
        </div>

        {/* Labels */}
        <div className="grid grid-cols-5 gap-1">
          {APPETITE_LEVELS.map((level, i) => (
            <div
              key={level.short}
              className="flex flex-col items-center text-center"
            >
              <span
                className={`text-[11px] font-semibold leading-tight ${
                  i === idx ? active.text : "text-muted-foreground"
                } ${i === idx ? "" : "opacity-60"}`}
              >
                {level.short}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Factor pills */}
      <div className="mt-5 pt-4 border-t border-border/50 flex flex-wrap gap-2 text-xs">
        <span className="text-muted-foreground font-medium self-center">
          Тооцооны үндэс:
        </span>
        <span className="rounded-full border px-2.5 py-1 bg-background/70 text-muted-foreground">
          Байгууллагын хэмжээ
        </span>
        <span className="rounded-full border px-2.5 py-1 bg-background/70 text-muted-foreground">
          Өгөгдлийн ангилал
        </span>
        <span className="rounded-full border px-2.5 py-1 bg-background/70 text-muted-foreground">
          Зохицуулалтын шаардлага
        </span>
        <span className="rounded-full border px-2.5 py-1 bg-background/70 text-muted-foreground">
          Интернетэд нээлттэй байдал
        </span>
        <span className="rounded-full border px-2.5 py-1 bg-background/70 text-muted-foreground">
          Хяналтын төлөвшил
        </span>
      </div>
    </div>
  );
}

function ProfileInfoTile({
  label,
  value,
  icon: Icon,
}: {
  label: string;
  value?: string | number;
  icon: React.ComponentType<{ className?: string }>;
}) {
  return (
    <div className="rounded-lg border bg-background/50 p-4">
      <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-muted-foreground">
        <Icon className="h-4 w-4 text-blue-600" />
        {label}
      </div>
      <p className="text-base font-semibold leading-snug">
        {value || "Оруулаагүй"}
      </p>
    </div>
  );
}

export default function OrganizationProfilePage() {
  const { user } = useAuth();
  const router = useRouter();
  const [formData, setFormData] = useState<OrganizationData>({
    organization_name: "",
    industry: "",
    size_category: "",
    description: "",
    risk_appetite: "",
    review_cadence_days: 90,
    risk_tolerance_thresholds: { low: 4, medium: 9, high: 16, critical: 25 },
    compliance_requirements: ["NIST CSF 2.0"],
    critical_business_services: "",
    risk_owner: "",
    security_owner: "",
    risk_acceptance_approver: "",
    review_triggers: ["Quarterly scheduled review"],
    sensitive_data_answers: SENSITIVE_DATA_DEFAULT_ANSWERS,
    inferred_data_classification: "Public",
    availability_impact_level: "",
    it_dependency_level: "",
  });

  const [loading, setLoading] = useState(false);
  const [saved, setSaved] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [hasData, setHasData] = useState(false);
  const [businessProcesses, setBusinessProcesses] = useState<
    CriticalBusinessProcess[]
  >([]);
  const [businessProcessInput, setBusinessProcessInput] = useState("");
  const [businessProcessSaving, setBusinessProcessSaving] = useState(false);
  const [businessProcessError, setBusinessProcessError] = useState("");
  const [editingProcessId, setEditingProcessId] = useState<number | null>(null);
  const [editingProcessName, setEditingProcessName] = useState("");

  useEffect(() => {
    if (!user) {
      router.push("/auth/login");
    } else {
      fetchOrganizationData();
      fetchBusinessProcesses();
    }
  }, [user, router]);

  const fetchOrganizationData = async () => {
    try {
      const response = await fetch("/api/profile");
      if (response.ok) {
        const data = await response.json();
        if (data.organization) {
          setFormData((prev) => ({
            ...prev,
            ...data.organization,
            compliance_requirements: normalizeStringArray(
              data.organization.compliance_requirements,
            ),
            review_triggers: normalizeStringArray(
              data.organization.review_triggers,
            ),
            sensitive_data_answers: normalizeSensitiveDataAnswers(
              data.organization.sensitive_data_answers,
            ),
            risk_tolerance_thresholds: {
              ...prev.risk_tolerance_thresholds,
              ...(data.organization.risk_tolerance_thresholds ?? {}),
            },
          }));
          setHasData(true);
          setIsEditing(false);
        }
      }
    } catch {
      console.log("Байгууллагын мэдээлэл олдсонгүй, шинээр эхэлж байна");
      setHasData(false);
    }
  };

  const fetchBusinessProcesses = async () => {
    try {
      const response = await fetch("/api/business-processes");
      if (!response.ok) throw new Error("Business process list fetch failed");
      const data = await response.json();
      const processes = Array.isArray(data.processes)
        ? data.processes.filter(
            (process: CriticalBusinessProcess) =>
              process.status !== "Inactive" &&
              String(process.criticality ?? "Critical").toLowerCase() ===
                "critical",
          )
        : [];
      setBusinessProcesses(processes);
      setBusinessProcessError("");
    } catch (error) {
      console.error("Жагсаалт татах үед алдаа гарлаа:", error);
      setBusinessProcesses([]);
      setBusinessProcessError(
        "Бизнесийн үйл ажиллагааны жагсаалт ачаалж чадсангүй.",
      );
    }
  };

  const handleAddBusinessProcess = async () => {
    const processName = businessProcessInput.trim();
    if (!processName) return;

    try {
      setBusinessProcessSaving(true);
      setBusinessProcessError("");
      const response = await fetch("/api/business-processes", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          process_name: processName,
          criticality: "Critical",
          status: "Active",
        }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok)
        throw new Error(
          data.error || "Бизнесийн үйл ажиллагаа бүртгэж чадсангүй.",
        );

      setBusinessProcessInput("");
      await fetchBusinessProcesses();
    } catch (error) {
      setBusinessProcessError(
        error instanceof Error
          ? error.message
          : "Бизнесийн үйл ажиллагаа бүртгэж чадсангүй.",
      );
    } finally {
      setBusinessProcessSaving(false);
    }
  };

  const handleRemoveBusinessProcess = async (
    process: CriticalBusinessProcess,
  ) => {
    if (
      !window.confirm(
        `"${process.process_name}" бизнесийн үйл ажиллагаа-ийг устгах уу?`,
      )
    )
      return;

    try {
      setBusinessProcessSaving(true);
      setBusinessProcessError("");
      const response = await fetch(
        `/api/business-processes?id=${encodeURIComponent(String(process.id))}`,
        { method: "DELETE" },
      );
      const data = await response.json().catch(() => ({}));
      if (!response.ok)
        throw new Error(
          data.error || "Бизнесийн үйл ажиллагаа устгаж чадсангүй.",
        );

      await fetchBusinessProcesses();
    } catch (error) {
      setBusinessProcessError(
        error instanceof Error
          ? error.message
          : "Бизнесийн үйл ажиллагаа устгаж чадсангүй.",
      );
    } finally {
      setBusinessProcessSaving(false);
    }
  };

  const handleEditBusinessProcess = (process: CriticalBusinessProcess) => {
    setEditingProcessId(process.id);
    setEditingProcessName(process.process_name);
    setBusinessProcessError("");
  };

  const handleCancelEditBusinessProcess = () => {
    setEditingProcessId(null);
    setEditingProcessName("");
  };

  const handleSaveBusinessProcess = async () => {
    if (editingProcessId == null) return;
    const trimmed = editingProcessName.trim();
    if (!trimmed) {
      setBusinessProcessError("Нэр хоосон байж болохгүй.");
      return;
    }

    try {
      setBusinessProcessSaving(true);
      setBusinessProcessError("");
      const response = await fetch("/api/business-processes", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: editingProcessId,
          process_name: trimmed,
        }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok)
        throw new Error(
          data.error || "Бизнесийн үйл ажиллагаа шинэчилж чадсангүй.",
        );

      setEditingProcessId(null);
      setEditingProcessName("");
      await fetchBusinessProcesses();
    } catch (error) {
      setBusinessProcessError(
        error instanceof Error
          ? error.message
          : "Бизнесийн үйл ажиллагаа шинэчилж чадсангүй.",
      );
    } finally {
      setBusinessProcessSaving(false);
    }
  };

  const handleInputChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>,
  ) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSelectChange = (name: string, value: string) => {
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleArrayToggle = (
    field: "compliance_requirements" | "review_triggers",
    value: string,
  ) => {
    setFormData((prev) => {
      const current = normalizeStringArray(prev[field]);
      const next = current.includes(value)
        ? current.filter((item) => item !== value)
        : [...current, value];

      return {
        ...prev,
        [field]: next,
      };
    });
  };

  const handleSensitiveDataToggle = (
    key: SensitiveMultiSelectKey,
    value: string,
  ) => {
    setFormData((prev) => {
      const currentAnswers = normalizeSensitiveDataAnswers(
        prev.sensitive_data_answers,
      );
      const currentValues = currentAnswers[key];
      const nextValues =
        value === NONE_VALUE
          ? currentValues.includes(NONE_VALUE)
            ? []
            : [NONE_VALUE]
          : currentValues.includes(value)
            ? currentValues.filter((item) => item !== value)
            : [...currentValues.filter((item) => item !== NONE_VALUE), value];
      const nextAnswers = { ...currentAnswers, [key]: nextValues };
      const inferredDataClassification = deriveDataClassification(nextAnswers);

      return {
        ...prev,
        sensitive_data_answers: nextAnswers,
        uses_sensitive_data: inferredDataClassification !== "Public",
        inferred_data_classification: inferredDataClassification,
      };
    });
  };

  const handleSensitiveSingleChange = (
    key: SensitiveSingleSelectKey,
    value: string,
  ) => {
    setFormData((prev) => {
      const currentAnswers = normalizeSensitiveDataAnswers(
        prev.sensitive_data_answers,
      );
      const nextAnswers = { ...currentAnswers, [key]: value };

      return {
        ...prev,
        sensitive_data_answers: nextAnswers,
        availability_impact_level: nextAnswers.availabilityImpact,
        it_dependency_level: nextAnswers.itDependency,
      };
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    const sensitiveDataAnswers = normalizeSensitiveDataAnswers(
      formData.sensitive_data_answers,
    );
    const inferredDataClassification =
      deriveDataClassification(sensitiveDataAnswers);

    try {
      const response = await fetch("/api/profile", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          ...formData,
          sensitive_data_answers: sensitiveDataAnswers,
          uses_sensitive_data: inferredDataClassification !== "Public",
          inferred_data_classification: inferredDataClassification,
          availability_impact_level: sensitiveDataAnswers.availabilityImpact,
          it_dependency_level: sensitiveDataAnswers.itDependency,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        setFormData((prev) => ({
          ...prev,
          ...(data.organization || formData),
          sensitive_data_answers: normalizeSensitiveDataAnswers(
            data.organization?.sensitive_data_answers ??
              formData.sensitive_data_answers,
          ),
        }));
        setHasData(true);
        setIsEditing(false);
        setSaved(true);
        setTimeout(() => setSaved(false), 3000);
      } else {
        alert("Байгууллагын мэдээллийг хадгалж чадсангүй");
      }
    } catch (error) {
      alert("Байгууллагын мэдээлэл хадгалах үед алдаа гарлаа");
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  if (!user) {
    return null;
  }

  // Display View
  if (hasData && !isEditing) {
    const thresholds = formData.risk_tolerance_thresholds ?? {};
    const sensitiveDataAnswers = normalizeSensitiveDataAnswers(
      formData.sensitive_data_answers,
    );
    const inferredDataClassification =
      formData.inferred_data_classification ||
      deriveDataClassification(sensitiveDataAnswers);
    const complianceRequirements = normalizeStringArray(
      formData.compliance_requirements,
    );
    const reviewTriggers = normalizeStringArray(formData.review_triggers);
    const calculatedRiskAppetite =
      formData.risk_appetite || calculateRiskAppetitePreview(formData);
    return (
      <div className="app-page app-readonly p-4 md:p-8 pb-8">
        <div className="mx-auto max-w-5xl space-y-6">
          <Card
            className={`${ORG_PROFILE_CARD_CLASS} overflow-hidden shadow-sm`}
          >
            <CardHeader className="border-b border-border pb-6">
              <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
                <div className="flex min-w-0 gap-4">
                  <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-xl bg-blue-500/10 text-blue-600">
                    <Building2 className="h-7 w-7" />
                  </div>
                  <div className="min-w-0">
                    <div className="mb-2 flex flex-wrap items-center gap-2">
                      <Badge className="border border-blue-500/20 bg-blue-500/10 text-blue-600">
                        Профайл
                      </Badge>
                    </div>
                    <CardTitle className="wrap-break-word text-3xl font-bold tracking-tight sm:text-3xl">
                      {formData.organization_name}
                    </CardTitle>
                  </div>
                </div>
                <Button
                  onClick={() => setIsEditing(true)}
                  variant="outline"
                  className="app-field shrink-0"
                >
                  <Pencil className="mr-2 h-4 w-4" />
                  Мэдээлэл өөрчлөх
                </Button>
              </div>
            </CardHeader>

            <CardContent className="space-y-6 pt-6">
              {/* ── Risk Appetite hero ── */}
              <RiskAppetiteHero appetiteLabel={calculatedRiskAppetite} />

              {/* ── Quick info tiles ── */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <ProfileInfoTile
                  label="Салбар"
                  value={formData.industry}
                  icon={Building2}
                />
                <ProfileInfoTile
                  label="Байгууллагын хэмжээ"
                  value={formData.size_category}
                  icon={Users}
                />
                <ProfileInfoTile
                  label="Дахин үнэлэх давтамж"
                  value={
                    formData.review_cadence_days
                      ? `${formData.review_cadence_days} хоног тутам`
                      : undefined
                  }
                  icon={CalendarClock}
                />
                <ProfileInfoTile
                  label="Өгөгдлийн ангилал"
                  value={formatDataClassification(inferredDataClassification)}
                  icon={FileText}
                />
              </div>

              <div className="rounded-lg border bg-background/50 p-4">
                <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-muted-foreground">
                  <ListChecks className="h-4 w-4 text-blue-600" />
                  Чухал бизнесийн үйл ажиллагаанууд
                </div>
                {businessProcesses.length > 0 ? (
                  <div className="grid gap-2 sm:grid-cols-2">
                    {businessProcesses.map((process) => (
                      <div
                        key={process.id}
                        className="rounded-md border border-border bg-background/60 px-3 py-2 text-sm font-medium"
                      >
                        {formatBusinessProcessLabel(process)}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    Чухал бизнесийн үйл ажиллагаа бүртгээгүй байна.
                  </p>
                )}
              </div>

              <div className="grid grid-cols-1 gap-4">
                <div className="rounded-lg border bg-background/50 p-4">
                  <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-muted-foreground">
                    <Scale className="h-4 w-4 text-blue-600" />
                    Эрсдэлийн босго оноо
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    {THRESHOLD_FIELDS.map((field) => (
                      <div
                        key={field.key}
                        className="rounded-md bg-muted px-3 py-2"
                      >
                        <p className="text-xs text-muted-foreground">
                          {field.label}
                        </p>
                        <p className="font-semibold">
                          ≤ {thresholds[field.key] ?? field.fallback}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
                <div className="rounded-lg border bg-background/50 p-4 lg:col-span-2">
                  <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-muted-foreground">
                    <Landmark className="h-4 w-4 text-blue-600" />
                    Дагаж мөрдөх шаардлага
                  </div>
                  {complianceRequirements.length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                      {complianceRequirements.map((item) => (
                        <Badge
                          key={item}
                          className="border border-blue-500/20 bg-blue-500/10 text-blue-600"
                        >
                          {formatComplianceRequirement(item)}
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground">
                      Дагаж мөрдөх шаардлага сонгоогүй байна.
                    </p>
                  )}
                </div>

                <div className="rounded-lg border bg-background/50 p-4">
                  <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-muted-foreground">
                    <ListChecks className="h-4 w-4 text-blue-600" />
                    Дахин хянах нөхцөл
                  </div>
                  <div className="space-y-2 text-sm">
                    {reviewTriggers.length > 0 ? (
                      reviewTriggers.map((trigger) => (
                        <div key={trigger} className="flex items-start gap-2">
                          <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 text-emerald-600" />
                          <span>{formatReviewTrigger(trigger)}</span>
                        </div>
                      ))
                    ) : (
                      <p className="text-muted-foreground">
                        Дахин хянах нөхцөл сонгоогүй байна.
                      </p>
                    )}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
                <div className="rounded-lg border bg-background/50 p-4 lg:col-span-2">
                  <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-muted-foreground">
                    <FileText className="h-4 w-4 text-blue-600" />
                    Эмзэг мэдээллийн тодорхойлолт
                  </div>
                  <div className="grid gap-3 text-sm md:grid-cols-3">
                    <div>
                      <p className="text-xs text-muted-foreground">
                        Хэрэглэгчийн эмзэг мэдээлэл
                      </p>
                      <p className="font-medium">
                        {hasSelectedValues(
                          sensitiveDataAnswers.customerSensitiveData,
                        )
                          ? "Ашигладаг"
                          : "Бүртгэгдээгүй"}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">
                        Хүртээмжийн нөлөө
                      </p>
                      <p className="font-medium">
                        {getImpactLabel(
                          sensitiveDataAnswers.availabilityImpact,
                        )}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">
                        IT хамаарал
                      </p>
                      <p className="font-medium">
                        {getImpactLabel(sensitiveDataAnswers.itDependency)}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">
                        Мэдээллийн хэмжээ
                      </p>
                      <p className="font-medium">
                        {getImpactLabel(sensitiveDataAnswers.dataVolume)}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">
                        Интернетэд нээлттэй байдал
                      </p>
                      <p className="font-medium">
                        {getImpactLabel(sensitiveDataAnswers.internetExposure)}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">
                        Хяналтын төлөвшил
                      </p>
                      <p className="font-medium">
                        {formatControlMaturityBaseline(
                          getControlMaturityBaseline(
                            sensitiveDataAnswers.securityCapabilities,
                          ),
                        )}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">
                        SaaS хамаарал
                      </p>
                      <p className="font-medium">
                        {getImpactLabel(
                          sensitiveDataAnswers.thirdPartyDependency,
                        )}
                      </p>
                    </div>
                  </div>
                </div>

                <div className="rounded-lg border bg-background/50 p-4">
                  <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-muted-foreground">
                    <Gauge className="h-4 w-4 text-blue-600" />
                    Тооцооллын үндэслэл
                  </div>
                  <p className="text-sm leading-6 text-muted-foreground">
                    {formData.risk_appetite_reason ||
                      "Асуулгын хариулт, байгууллагын хэмжээ болон шаардлагуудаас тооцоолно."}
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-4">
                <div className="rounded-lg border bg-background/50 p-4">
                  <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-muted-foreground">
                    <UserCheck className="h-4 w-4 text-blue-600" />
                    Хариуцсан эзэмшигчид
                  </div>
                  <div className="space-y-3 text-sm">
                    {[
                      ["Эрсдэлийг хариуцагч", formData.risk_owner],
                      ["Аюулгүй байдлын хариуцагч", formData.security_owner],
                      [
                        "Эрсдэлийг хүлээн зөвшөөрөх C түвшний ажилтан",
                        formData.risk_acceptance_approver,
                      ],
                    ].map(([label, value]) => (
                      <div key={label}>
                        <p className="text-xs text-muted-foreground">{label}</p>
                        <p className="font-medium">{value || "Томилоогүй"}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  // Edit Form View
  return (
    <div className="app-page p-4 md:p-8 pb-8">
      <div className="max-w-6xl mx-auto space-y-6">
        <Card className={`${ORG_PROFILE_CARD_CLASS} overflow-hidden shadow-sm`}>
          <CardHeader className="border-b border-border pb-6">
            <CardTitle>Байгууллагын мэдээлэл</CardTitle>
            <CardDescription>
              Доорх мэдээллийг оруулснаар танай байгууллагын эрсдэлийг хүлээж
              авах хэмжээ болон үйл ажиллагаандаа эмзэг мэдээлэл ашигладаг
              эсэхийг тодорхойлно.
            </CardDescription>
          </CardHeader>
          <CardContent className="p-4 sm:p-6 md:p-8">
            <form onSubmit={handleSubmit} className="space-y-6">
              {/* Organization Name */}
              <div className="grid gap-3">
                <Label htmlFor="organization_name" className="font-semibold">
                  Байгууллагын нэр
                </Label>
                <Input
                  id="organization_name"
                  name="organization_name"
                  placeholder="Танай байгууллагын нэр"
                  value={formData.organization_name}
                  onChange={handleInputChange}
                  className={ORG_FORM_FIELD_CLASS}
                  required
                />
              </div>

              {/* Industry and Size */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="grid gap-3">
                  <Label htmlFor="industry" className="font-semibold">
                    Салбар
                  </Label>
                  <Select
                    value={formData.industry}
                    onValueChange={(value) =>
                      handleSelectChange("industry", value)
                    }
                  >
                    <SelectTrigger className={ORG_FORM_FIELD_CLASS}>
                      <SelectValue placeholder="Салбар сонгоно уу" />
                    </SelectTrigger>
                    <SelectContent className={ORG_SELECT_CONTENT_CLASS}>
                      {INDUSTRY_OPTIONS.map((industry) => (
                        <SelectItem
                          key={industry}
                          value={industry}
                          className={ORG_SELECT_ITEM_CLASS}
                        >
                          {industry}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="grid gap-3">
                  <Label htmlFor="size_category" className="font-semibold">
                    Байгууллагын хэмжээ
                  </Label>
                  <Select
                    value={formData.size_category}
                    onValueChange={(value) =>
                      handleSelectChange("size_category", value)
                    }
                  >
                    <SelectTrigger className={ORG_FORM_FIELD_CLASS}>
                      <SelectValue placeholder="Байгууллагын хэмжээ сонгоно уу" />
                    </SelectTrigger>
                    <SelectContent className={ORG_SELECT_CONTENT_CLASS}>
                      {SIZE_CATEGORIES.map((size) => (
                        <SelectItem
                          key={size}
                          value={size}
                          className={ORG_SELECT_ITEM_CLASS}
                        >
                          {size}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {/* Critical Business Processes */}
              <div className="grid gap-3">
                <Label className="font-semibold">
                  Байгууллагын чухал бизнесийн үйл ажиллагаанууд
                </Label>
                <div className={ORG_FORM_PANEL_CLASS}>
                  <div className="flex flex-col gap-2 sm:flex-row">
                    <Input
                      value={businessProcessInput}
                      onChange={(e) => {
                        setBusinessProcessInput(e.target.value);
                        setBusinessProcessError("");
                      }}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          handleAddBusinessProcess();
                        }
                      }}
                      placeholder="Жишээ нь: Төлбөр тооцоо, Захиалга хүргэлт"
                      className={ORG_FORM_FIELD_CLASS}
                    />
                    <Button
                      type="button"
                      onClick={handleAddBusinessProcess}
                      disabled={
                        businessProcessSaving ||
                        businessProcessInput.trim().length === 0
                      }
                      className="shrink-0 bg-blue-600 text-white hover:bg-blue-700"
                    >
                      <Plus className="h-4 w-4" />
                      Нэмэх
                    </Button>
                  </div>

                  {businessProcessError && (
                    <p className="mt-3 text-sm font-medium text-red-600 dark:text-red-400">
                      {businessProcessError}
                    </p>
                  )}

                  <div className="mt-4 grid gap-2">
                    {businessProcesses.length > 0 ? (
                      businessProcesses.map((process) => {
                        const isEditing = editingProcessId === process.id;
                        return (
                          <div
                            key={process.id}
                            className="flex items-center justify-between gap-3 rounded-md border border-border bg-background/60 px-3 py-2"
                          >
                            {isEditing ? (
                              <Input
                                value={editingProcessName}
                                onChange={(e) =>
                                  setEditingProcessName(e.target.value)
                                }
                                onKeyDown={(e) => {
                                  if (e.key === "Enter") {
                                    e.preventDefault();
                                    handleSaveBusinessProcess();
                                  } else if (e.key === "Escape") {
                                    e.preventDefault();
                                    handleCancelEditBusinessProcess();
                                  }
                                }}
                                disabled={businessProcessSaving}
                                autoFocus
                                className="h-8 text-sm"
                              />
                            ) : (
                              <p className="min-w-0 text-sm font-medium">
                                {formatBusinessProcessLabel(process)}
                              </p>
                            )}
                            <div className="flex shrink-0 items-center gap-1">
                              {isEditing ? (
                                <>
                                  <Button
                                    type="button"
                                    variant="ghost"
                                    size="icon-sm"
                                    onClick={handleSaveBusinessProcess}
                                    disabled={
                                      businessProcessSaving ||
                                      editingProcessName.trim().length === 0
                                    }
                                    title="Хадгалах"
                                    aria-label="Хадгалах"
                                  >
                                    <Check className="h-4 w-4 text-emerald-600" />
                                  </Button>
                                  <Button
                                    type="button"
                                    variant="ghost"
                                    size="icon-sm"
                                    onClick={handleCancelEditBusinessProcess}
                                    disabled={businessProcessSaving}
                                    title="Болих"
                                    aria-label="Болих"
                                  >
                                    <X className="h-4 w-4 text-muted-foreground" />
                                  </Button>
                                </>
                              ) : (
                                <>
                                  <Button
                                    type="button"
                                    variant="ghost"
                                    size="icon-sm"
                                    onClick={() =>
                                      handleEditBusinessProcess(process)
                                    }
                                    disabled={
                                      businessProcessSaving ||
                                      editingProcessId !== null
                                    }
                                    title="Засах"
                                    aria-label="Бизнесийн үйл ажиллагаа засах"
                                  >
                                    <Pencil className="h-4 w-4 text-blue-600" />
                                  </Button>
                                  <Button
                                    type="button"
                                    variant="ghost"
                                    size="icon-sm"
                                    onClick={() =>
                                      handleRemoveBusinessProcess(process)
                                    }
                                    disabled={
                                      businessProcessSaving ||
                                      editingProcessId !== null
                                    }
                                    title="Устгах"
                                    aria-label="Бизнесийн үйл ажиллагаа устгах"
                                  >
                                    <Trash2 className="h-4 w-4 text-red-600" />
                                  </Button>
                                </>
                              )}
                            </div>
                          </div>
                        );
                      })
                    ) : (
                      <p className="text-sm text-muted-foreground">
                        Одоогоор чухал бизнесийн үйл ажиллагаа бүртгээгүй байна.
                      </p>
                    )}
                  </div>
                </div>
              </div>

              {/* Sensitive Data Identification */}
              <div className="grid gap-4">
                <div className="grid gap-4">
                  {SENSITIVE_DATA_MULTI_QUESTIONS.map((question) => {
                    const answers = normalizeSensitiveDataAnswers(
                      formData.sensitive_data_answers,
                    );
                    const selectedValues = answers[question.key];

                    return (
                      <div key={question.key} className={ORG_FORM_PANEL_CLASS}>
                        <div className="mb-3">
                          <p className="mt-1 font-semibold">
                            {question.question}
                          </p>
                        </div>
                        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                          {question.options.map((option) => (
                            <label
                              key={option.value}
                              className={ORG_OPTION_CLASS}
                            >
                              <input
                                type="checkbox"
                                className={`${ORG_CHOICE_INPUT_CLASS} rounded`}
                                checked={selectedValues.includes(option.value)}
                                onChange={() =>
                                  handleSensitiveDataToggle(
                                    question.key,
                                    option.value,
                                  )
                                }
                              />
                              <span>{option.label}</span>
                            </label>
                          ))}
                        </div>
                      </div>
                    );
                  })}

                  {SENSITIVE_DATA_SINGLE_QUESTIONS.map((question) => {
                    const answers = normalizeSensitiveDataAnswers(
                      formData.sensitive_data_answers,
                    );

                    return (
                      <div key={question.key} className={ORG_FORM_PANEL_CLASS}>
                        <div className="mb-3">
                          <p className="mt-1 font-semibold">
                            {question.question}
                          </p>
                        </div>
                        <div className="grid grid-cols-1 gap-2 sm:grid-cols-4">
                          {question.options.map((option) => (
                            <label
                              key={option.value}
                              className={ORG_OPTION_CLASS}
                            >
                              <input
                                type="radio"
                                name={question.key}
                                className={ORG_CHOICE_INPUT_CLASS}
                                checked={answers[question.key] === option.value}
                                onChange={() =>
                                  handleSensitiveSingleChange(
                                    question.key,
                                    option.value,
                                  )
                                }
                              />
                              <span>{option.label}</span>
                            </label>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>

                <div className={ORG_FORM_PANEL_CLASS}>
                  <div className="grid gap-3 text-sm md:grid-cols-3 xl:grid-cols-4">
                    <div>
                      <p className="text-xs font-semibold uppercase text-muted-foreground">
                        Өгөгдлийн ангилал
                      </p>
                      <p className="mt-1 text-base font-semibold">
                        {formatDataClassification(
                          deriveDataClassification(
                            normalizeSensitiveDataAnswers(
                              formData.sensitive_data_answers,
                            ),
                          ),
                        )}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs font-semibold uppercase text-muted-foreground">
                        Хэрэглэгчийн эмзэг мэдээлэл
                      </p>
                      <p className="mt-1 text-base font-semibold">
                        {hasSelectedValues(
                          normalizeSensitiveDataAnswers(
                            formData.sensitive_data_answers,
                          ).customerSensitiveData,
                        )
                          ? "Тийм"
                          : "Үгүй"}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs font-semibold uppercase text-muted-foreground">
                        Эрсдэлийн хүлээж авах хэмжээ
                      </p>
                      <p className="mt-1 text-base font-semibold">
                        {calculateRiskAppetitePreview(formData)}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs font-semibold uppercase text-muted-foreground">
                        Хэрэглэгчийн тоо хэмжээ
                      </p>
                      <p className="mt-1 text-base font-semibold">
                        {getImpactLabel(
                          normalizeSensitiveDataAnswers(
                            formData.sensitive_data_answers,
                          ).dataVolume,
                        )}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs font-semibold uppercase text-muted-foreground">
                        Хандах орчин
                      </p>
                      <p className="mt-1 text-base font-semibold">
                        {getImpactLabel(
                          normalizeSensitiveDataAnswers(
                            formData.sensitive_data_answers,
                          ).internetExposure,
                        )}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs font-semibold uppercase text-muted-foreground">
                        Хяналтын төлөвшил
                      </p>
                      <p className="mt-1 text-base font-semibold">
                        {formatControlMaturityBaseline(
                          getControlMaturityBaseline(
                            normalizeSensitiveDataAnswers(
                              formData.sensitive_data_answers,
                            ).securityCapabilities,
                          ),
                        )}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs font-semibold uppercase text-muted-foreground">
                        SaaS хамаарал
                      </p>
                      <p className="mt-1 text-base font-semibold">
                        {getImpactLabel(
                          normalizeSensitiveDataAnswers(
                            formData.sensitive_data_answers,
                          ).thirdPartyDependency,
                        )}
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Compliance Requirements */}
              <div className="grid gap-3">
                <Label className="font-semibold">
                  Дараах хууль болон стандарт шаардлагуудаас алийг нь дагаж
                  мөрддөг вэ ?
                </Label>
                <div
                  className={`${ORG_FORM_PANEL_CLASS} grid grid-cols-1 gap-2 sm:grid-cols-2`}
                >
                  {COMPLIANCE_OPTIONS.map((item) => (
                    <label
                      key={item.value}
                      className="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm"
                    >
                      <input
                        type="checkbox"
                        className={`${ORG_CHOICE_INPUT_CLASS} rounded`}
                        checked={normalizeStringArray(
                          formData.compliance_requirements,
                        ).includes(item.value)}
                        onChange={() =>
                          handleArrayToggle(
                            "compliance_requirements",
                            item.value,
                          )
                        }
                      />
                      <span>{item.label}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Governance Owners */}
              <div className="grid gap-3">
                <Label className="text-xl font-bold">
                  Засаглал хариуцагчид
                </Label>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                  <div className="grid gap-2">
                    <Label htmlFor="risk_owner" className="text-sm">
                      Эрсдэл хариуцагч
                    </Label>
                    <Input
                      id="risk_owner"
                      name="risk_owner"
                      placeholder="Жишээ нь: Эрсдэлийн захирал"
                      value={formData.risk_owner || ""}
                      onChange={handleInputChange}
                      className={ORG_FORM_FIELD_CLASS}
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="security_owner" className="text-sm">
                      Аюулгүй байдлын эзэмшигч
                    </Label>
                    <Input
                      id="security_owner"
                      name="security_owner"
                      placeholder="Жишээ нь: Аюулгүй байдлын менежер"
                      value={formData.security_owner || ""}
                      onChange={handleInputChange}
                      className={ORG_FORM_FIELD_CLASS}
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label
                      htmlFor="risk_acceptance_approver"
                      className="text-sm"
                    >
                      Эрсдэлийг хүлээн зөвшөөрөх батлагч
                    </Label>
                    <Input
                      id="risk_acceptance_approver"
                      name="risk_acceptance_approver"
                      placeholder="Жишээ нь: CISO эсвэл удирдлагын төлөөлөл"
                      value={formData.risk_acceptance_approver || ""}
                      onChange={handleInputChange}
                      className={ORG_FORM_FIELD_CLASS}
                    />
                  </div>
                </div>
              </div>

              {/* Risk Appetite */}
              <div className="grid gap-3">
                <Label className="font-semibold">
                  Тооцоолсон эрсдэлийг хүлээж авах түвшин
                </Label>
                <div className={ORG_FORM_PANEL_CLASS}>
                  <div className="flex items-start gap-3">
                    <Gauge className="mt-0.5 h-5 w-5 shrink-0 text-blue-600" />
                    <div className="space-y-1">
                      <p className="font-semibold">
                        {calculateRiskAppetitePreview(formData)}
                      </p>
                      <p className="text-sm text-muted-foreground">
                        Байгууллагын салбар, хэмжээ эмзэг мэдээллийн ашиглалт
                        болон дагаж мөрддөг хууль журам, шаардлагуудад суурилан
                        тодорхойлов.
                      </p>
                      {typeof formData.sensitive_asset_count === "number" && (
                        <p className="text-sm text-muted-foreground">
                          Эмзэг мэдээлэл боловсруулдаг хөрөнгийн тоо:{" "}
                          {formData.sensitive_asset_count}
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {/* Re-assessment Cadence */}
              <div className="grid gap-3">
                <Label htmlFor="review_cadence_days" className="font-semibold">
                  Дахин үнэлэх давтамж
                </Label>
                <Select
                  value={String(formData.review_cadence_days ?? 90)}
                  onValueChange={(value) =>
                    setFormData((prev) => ({
                      ...prev,
                      review_cadence_days: Number(value),
                    }))
                  }
                >
                  <SelectTrigger className={ORG_FORM_FIELD_CLASS}>
                    <SelectValue placeholder="Давтамж сонгоно уу" />
                  </SelectTrigger>
                  <SelectContent className={ORG_SELECT_CONTENT_CLASS}>
                    {REVIEW_CADENCE_OPTIONS.map((opt) => (
                      <SelectItem
                        key={opt.value}
                        value={String(opt.value)}
                        className={ORG_SELECT_ITEM_CLASS}
                      >
                        {opt.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-sm text-muted-foreground mt-2">
                  Маш чухал хөрөнгийг үндсэн давтамжаас илүү ойр давтамжтайгаар
                  хянана.
                </p>
              </div>

              {/* Review Triggers */}
              <div className="grid gap-3">
                <Label className="font-semibold">Дахин үнэлэх нөхцөлүүд</Label>
                <div
                  className={`${ORG_FORM_PANEL_CLASS} grid grid-cols-1 gap-2 sm:grid-cols-2`}
                >
                  {REVIEW_TRIGGER_OPTIONS.map((item) => (
                    <label
                      key={item.value}
                      className="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm"
                    >
                      <input
                        type="checkbox"
                        className={`${ORG_CHOICE_INPUT_CLASS} rounded`}
                        checked={normalizeStringArray(
                          formData.review_triggers,
                        ).includes(item.value)}
                        onChange={() =>
                          handleArrayToggle("review_triggers", item.value)
                        }
                      />
                      <span>{item.label}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Submit Button */}
              <div className="flex gap-4 pt-6 border-t border-border">
                <Button
                  type="submit"
                  disabled={loading}
                  className="bg-blue-600 hover:bg-blue-700 text-white font-semibold px-6"
                >
                  {loading ? "Хадгалж байна..." : "Хадгалах"}
                </Button>
                {hasData && (
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setIsEditing(false)}
                    className="app-field"
                  >
                    Болих
                  </Button>
                )}
                {saved && (
                  <p className="text-green-600 dark:text-green-400 font-semibold self-center">
                    ✓ Байгууллагын мэдээлэл амжилттай хадгалагдлаа
                  </p>
                )}
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
