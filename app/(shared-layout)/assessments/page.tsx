"use client";

import { useAuth } from "@/app/context/AuthContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  AlertTriangle,
  BookOpen,
  Building2,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Database,
  FileText,
  GitBranch,
  Globe2,
  MapPin,
  RefreshCw,
  Save,
  Scale,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Users,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

// ─── Types ────────────────────────────────────────────────────────────────────

type RiskLevel = "Low" | "Medium" | "High" | "Critical" | "Unknown";
type Method = "asset_threat" | "framework";
type SubjectType =
  | "asset"
  | "process"
  | "vendor"
  | "policy"
  | "personnel"
  | "location"
  | "compliance";

const SUBJECT_META: Record<
  SubjectType,
  {
    mn: string;
    en: string;
    icon: React.ElementType;
    color: string;
    ring: string;
    badge: string;
    desc: string;
  }
> = {
  asset: {
    mn: "Систем",
    en: "Asset",
    icon: Database,
    color: "bg-sky-500",
    ring: "ring-sky-400/30 border-sky-300 bg-sky-50 dark:bg-sky-950/30",
    badge:
      "border-sky-200 bg-sky-100 text-sky-800 dark:border-sky-900 dark:bg-sky-950/40 dark:text-sky-300",
    desc: "Сервер, апп, өгөгдөл, төхөөрөмж",
  },
  process: {
    mn: "Үйл явц",
    en: "Process",
    icon: GitBranch,
    color: "bg-violet-500",
    ring: "ring-violet-400/30 border-violet-300 bg-violet-50 dark:bg-violet-950/30",
    badge:
      "border-violet-200 bg-violet-100 text-violet-800 dark:border-violet-900 dark:bg-violet-950/40 dark:text-violet-300",
    desc: "Бизнес үйл явц, журам, шийдвэр",
  },
  vendor: {
    mn: "Гуравдагч этгээд",
    en: "Vendor",
    icon: Building2,
    color: "bg-amber-500",
    ring: "ring-amber-400/30 border-amber-300 bg-amber-50 dark:bg-amber-950/30",
    badge:
      "border-amber-200 bg-amber-100 text-amber-800 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-300",
    desc: "Үйлчилгээ үзүүлэгч, нийлүүлэгч",
  },
  policy: {
    mn: "Бодлого",
    en: "Policy",
    icon: FileText,
    color: "bg-rose-500",
    ring: "ring-rose-400/30 border-rose-300 bg-rose-50 dark:bg-rose-950/30",
    badge:
      "border-rose-200 bg-rose-100 text-rose-800 dark:border-rose-900 dark:bg-rose-950/40 dark:text-rose-300",
    desc: "Дүрэм, журам, баримт бичиг",
  },
  personnel: {
    mn: "Хүний нөөц",
    en: "Personnel",
    icon: Users,
    color: "bg-pink-500",
    ring: "ring-pink-400/30 border-pink-300 bg-pink-50 dark:bg-pink-950/30",
    badge:
      "border-pink-200 bg-pink-100 text-pink-800 dark:border-pink-900 dark:bg-pink-950/40 dark:text-pink-300",
    desc: "Ажилтан, дотоод хэрэглэгч",
  },
  location: {
    mn: "Байршил",
    en: "Location",
    icon: MapPin,
    color: "bg-emerald-500",
    ring: "ring-emerald-400/30 border-emerald-300 bg-emerald-50 dark:bg-emerald-950/30",
    badge:
      "border-emerald-200 bg-emerald-100 text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-300",
    desc: "Оффис, дата төв, бие даасан салбар",
  },
  compliance: {
    mn: "Хууль зүй",
    en: "Compliance",
    icon: Scale,
    color: "bg-cyan-500",
    ring: "ring-cyan-400/30 border-cyan-300 bg-cyan-50 dark:bg-cyan-950/30",
    badge:
      "border-cyan-200 bg-cyan-100 text-cyan-800 dark:border-cyan-900 dark:bg-cyan-950/40 dark:text-cyan-300",
    desc: "Зохицуулалт, гэрээ, хууль",
  },
};

type ThreatOption = {
  id: number;
  threat_name: string;
  description: string | null;
  threat_type: string | null;
  likelihood_level: number | null;
  potential_impact: string | null;
  nist_category: string | null;
  risk_level: RiskLevel | null;
  mitigation_notes: string | null;
  is_related: boolean;
};

type AssetOption = {
  id: number;
  asset_name: string;
  asset_type: string | null;
  criticality: string | null;
  data_classification: string | null;
  internet_exposed: boolean;
};

type AssetThreatMapping = {
  asset_id: number;
  asset_name: string;
  asset_type: string | null;
  criticality: string | null;
  internet_exposed: boolean;
  mapped_threat_count: number;
  highest_risk: string;
  threats: ThreatOption[];
};

type WizardRisk = {
  key: string;
  asset_id: number;
  asset_name: string;
  asset_type: string | null;
  asset_criticality: string | null;
  threat_id: number;
  threat_name: string;
  threat_type: string | null;
  nist_category: string | null;
  risk_title: string;
  vulnerability_description: string;
  key_controls: string;
  selected_control_ids: string[];
  risk_owner: string;
  dept_owner: string;
  nist_csf_function: string;
  nist_csf_category: string;
  likelihood: number;
  impact: number;
  treatment: string | null;
  saved: boolean;
  db_id?: number;
  control_effectiveness: Record<string, number>;
  residual_risk_score: number | null;
  residual_risk_level: RiskLevel | null;
  custom_controls: string;
};

type SavedRisk = {
  id: number;
  risk_id: string;
  risk_code: string;
  asset_id: number | null;
  threat_id: number | null;
  asset_name: string | null;
  threat_name: string | null;
  risk_title: string;
  nist_csf_category: string | null;
  inherent_likelihood: number;
  inherent_impact: number;
  inherent_risk_score: number;
  inherent_risk_level: RiskLevel;
  residual_risk_level: RiskLevel | null;
  status: string | null;
  created_at: string;
};

type VulnerabilityOption = {
  asset_id: number | null;
  threat_id: number | null;
  status: string | null;
};

type ScopeDepartment = {
  id: number;
  department_name: string;
};

type ScopePayload = {
  departments?: ScopeDepartment[];
  assessment_scope?: {
    selected_department_ids?: number[];
  };
};

type NistControlOption = {
  id: number;
  control_id: string;
  domain: string | null;
  control_name: string | null;
  description: string | null;
  nist_csf_function: string | null;
  nist_csf_category: string | null;
  implementation_note: string | null;
  priority: number | null;
};

// ─── Constants ────────────────────────────────────────────────────────────────

const STEPS = [
  { label: "Хөрөнгө", sublabel: "Хөрөнгө сонгох" },
  { label: "Эрсдэл", sublabel: "Тохирох эрсдэл сонгох" },
  { label: "Эмзэг байдал", sublabel: "Эмзэг байдлын тайлбар" },
  { label: "Үнэлгээ", sublabel: "Магадлал ба нөлөөлөл" },
  { label: "Хяналт", sublabel: "Хяналт сонгох" },
  { label: "Үлдэгдэл", sublabel: "Хяналтын үр нөлөө тооцоолох" },
  { label: "Хадгалах", sublabel: "Хянах ба батлах" },
];

const LIKELIHOOD_LABELS: Record<number, string> = {
  1: "Маш бага",
  2: "Бага",
  3: "Дундаж",
  4: "Их",
  5: "Маш их",
};

const IMPACT_LABELS: Record<number, string> = {
  1: "Мэдэгдэхгүй",
  2: "Бага",
  3: "Дунд",
  4: "Их",
  5: "Маш их",
};

const LEVEL_STYLE: Record<string, string> = {
  Critical:
    "border-red-200 bg-red-100 text-red-800 dark:border-red-900 dark:bg-red-950/50 dark:text-red-300",
  High: "border-orange-200 bg-orange-100 text-orange-800 dark:border-orange-900 dark:bg-orange-950/50 dark:text-orange-300",
  Medium:
    "border-amber-200 bg-amber-100 text-amber-800 dark:border-amber-900 dark:bg-amber-950/50 dark:text-amber-300",
  Low: "border-emerald-200 bg-emerald-100 text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/50 dark:text-emerald-300",
  Unknown:
    "border-slate-200 bg-slate-100 text-slate-600 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300",
  None: "border-slate-200 bg-slate-100 text-slate-600 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300",
};

// NIST CSF framework-based risk templates
const FRAMEWORK_RISKS: Array<{
  function_code: string;
  function_mn: string;
  category_code: string;
  category_name: string;
  risk_title: string;
  vulnerability_description: string;
  subject_types: SubjectType[];
}> = [
  // ── ASSET-based ─────────────────────────────────────────────────────────
  {
    function_code: "ID",
    function_mn: "Таних",
    category_code: "ID.AM",
    category_name: "Asset Management",
    risk_title: "Бүртгэлгүй хөрөнгөөс үүдэх эрсдэл",
    vulnerability_description:
      "Мэдээллийн технологийн хөрөнгийн бүртгэл бүрэн биш, хуучирсан хөрөнгүүд байж болзошгүй.",
    subject_types: ["asset"],
  },
  {
    function_code: "PR",
    function_mn: "Хамгаалах",
    category_code: "PR.DS",
    category_name: "Data Security",
    risk_title: "Мэдээлэл шифрлэгдэхгүй байна",
    vulnerability_description:
      "Нууц мэдээлэл дамжуулах болон хадгалах явцад шифрлэгдэхгүй, задрах эрсдэлтэй.",
    subject_types: ["asset"],
  },
  {
    function_code: "PR",
    function_mn: "Хамгаалах",
    category_code: "PR.PS",
    category_name: "Platform Security",
    risk_title: "Тохируулгын алдаанаас үүдэх эрсдэл",
    vulnerability_description:
      "Системийн тохируулга буруу, хамгаалалтын нөөц идэвхжүүлэгдэхгүй байна.",
    subject_types: ["asset"],
  },
  {
    function_code: "DE",
    function_mn: "Илрүүлэх",
    category_code: "DE.CM",
    category_name: "Continuous Monitoring",
    risk_title: "Системийн үйл ажиллагааны хяналт хангалтгүй",
    vulnerability_description:
      "Аюулт үйлдлийг цаг тухайд нь илрүүлэх тасралтгүй хяналтын механизм байхгүй.",
    subject_types: ["asset", "process"],
  },

  // ── PROCESS-based ───────────────────────────────────────────────────────
  {
    function_code: "ID",
    function_mn: "Таних",
    category_code: "ID.RA",
    category_name: "Risk Assessment",
    risk_title: "Тогтмол эрсдэлийн үнэлгээ хийгдэхгүй байна",
    vulnerability_description:
      "Байгууллагын эрсдэлийн үнэлгээ тогтмол хийгдэхгүй, шинэ аюулыг цаг тухайд нь илрүүлэхгүй.",
    subject_types: ["process"],
  },
  {
    function_code: "DE",
    function_mn: "Илрүүлэх",
    category_code: "DE.AE",
    category_name: "Adverse Event Analysis",
    risk_title: "Аюулт үйлдлийн шинжилгээ хийгдэхгүй",
    vulnerability_description:
      "Аюулт үйлдлийг илрүүлсний дараа шинжилгээ хийх журам байхгүй.",
    subject_types: ["process"],
  },
  {
    function_code: "RS",
    function_mn: "Хариу үйлдэл",
    category_code: "RS.MA",
    category_name: "Incident Management",
    risk_title: "Аюулт явдлын хариу үйлдлийн төлөвлөгөөгүй",
    vulnerability_description:
      "Кибер аюулт явдалд хариу үйлдэл үзүүлэх журам, нэгжийн бэлэн байдал хангалтгүй.",
    subject_types: ["process"],
  },
  {
    function_code: "RC",
    function_mn: "Сэргээх",
    category_code: "RC.RP",
    category_name: "Recovery Execution",
    risk_title: "Системийн сэргээлтийн төлөвлөгөөгүй",
    vulnerability_description:
      "Мэдээллийн систем доголдсон үед сэргээх тодорхой журам, тест хийгдэхгүй байна.",
    subject_types: ["process", "asset"],
  },
  {
    function_code: "GV",
    function_mn: "Засаглал",
    category_code: "GV.OV",
    category_name: "Oversight",
    risk_title: "Гүйцэтгэлийн хяналт байхгүй",
    vulnerability_description:
      "Кибер аюулгүй байдлын бодлого хэрхэн биелж байгааг хянах хэлбэр байхгүй, ил тод биш.",
    subject_types: ["process"],
  },

  // ── VENDOR / SUPPLY CHAIN ───────────────────────────────────────────────
  {
    function_code: "GV",
    function_mn: "Засаглал",
    category_code: "GV.SC",
    category_name: "Supply Chain Risk",
    risk_title: "Гуравдагч этгээдийн аюулгүй байдлын үнэлгээ хийгдээгүй",
    vulnerability_description:
      "Үйлчилгээ үзүүлэгчийг сонгохдоо аюулгүй байдлын шалгуур (due diligence) хэрэглэгддэггүй.",
    subject_types: ["vendor"],
  },
  {
    function_code: "GV",
    function_mn: "Засаглал",
    category_code: "GV.SC",
    category_name: "Supply Chain Risk",
    risk_title: "Гэрээнд аюулгүй байдлын шалгуур тусгагдаагүй",
    vulnerability_description:
      "Үйлчилгээ үзүүлэгчийн гэрээнд SLA, мэдээлэл хамгаалал, нууцлалын заалт хангалтгүй.",
    subject_types: ["vendor", "compliance"],
  },
  {
    function_code: "GV",
    function_mn: "Засаглал",
    category_code: "GV.SC",
    category_name: "Supply Chain Monitoring",
    risk_title: "Үйлчилгээ үзүүлэгчид тогтмол үнэлгээ хийгддэггүй",
    vulnerability_description:
      "Чухал үйлчилгээ үзүүлэгчдийн аюулгүй байдлын төлөв жил бүр дахин шалгагдахгүй, тасралтгүй хяналт байхгүй.",
    subject_types: ["vendor"],
  },
  {
    function_code: "ID",
    function_mn: "Таних",
    category_code: "ID.AM",
    category_name: "Vendor Inventory",
    risk_title: "Гуравдагч этгээдийн бүртгэл байхгүй",
    vulnerability_description:
      "Ямар үйлчилгээ үзүүлэгчтэй ямар мэдээлэл хуваалцаж байгаа нь тодорхойгүй.",
    subject_types: ["vendor"],
  },
  {
    function_code: "PR",
    function_mn: "Хамгаалах",
    category_code: "PR.AA",
    category_name: "Third-party Access Control",
    risk_title: "Үйлчилгээ үзүүлэгчийн хандалт хяналтгүй",
    vulnerability_description:
      "Гуравдагч этгээдийн хэрэглэгчдэд хамгийн бага эрх, MFA, тогтоосон хугацаатай хандалт хэрэгжүүлэгдэхгүй байна.",
    subject_types: ["vendor"],
  },
  {
    function_code: "PR",
    function_mn: "Хамгаалах",
    category_code: "PR.DS",
    category_name: "Third-party Data Protection",
    risk_title: "Үйлчилгээ үзүүлэгчтэй хуваалцсан мэдээлэл хамгаалагдаагүй",
    vulnerability_description:
      "Гуравдагч этгээдэд дамжуулсан болон тэндэх хадгалагдсан нууц мэдээлэл шифрлэгдэхгүй, DLP-р хяналтгүй.",
    subject_types: ["vendor"],
  },
  {
    function_code: "PR",
    function_mn: "Хамгаалах",
    category_code: "PR.PS",
    category_name: "Vendor Platform Security",
    risk_title: "Үйлчилгээ үзүүлэгчийн систем шинэчлэгдэхгүй",
    vulnerability_description:
      "Үйлчилгээ үзүүлэгчийн платформ, ашиглаж буй ПО-н эмзэг байдал, патч менежмент батлагдаагүй.",
    subject_types: ["vendor"],
  },
  {
    function_code: "DE",
    function_mn: "Илрүүлэх",
    category_code: "DE.CM",
    category_name: "Third-party Connection Monitoring",
    risk_title: "Гуравдагч этгээдийн холболтод хяналт байхгүй",
    vulnerability_description:
      "Vendor-ийн API, VPN, integration сувгуудын лог, гажуудал, аюулт үйлдлийг тасралтгүй хянадаггүй.",
    subject_types: ["vendor"],
  },
  {
    function_code: "RS",
    function_mn: "Хариу үйлдэл",
    category_code: "RS.CO",
    category_name: "Third-party Incident Notification",
    risk_title: "Үйлчилгээ үзүүлэгчээс мэдэгдэх журам гэрээнд байхгүй",
    vulnerability_description:
      "Vendor өөрсдөд нь аюулт явдал гарвал биднийг хэдэн цагт мэдэгдэх SLA гэрээнд тусгагдаагүй.",
    subject_types: ["vendor"],
  },
  {
    function_code: "RS",
    function_mn: "Хариу үйлдэл",
    category_code: "RS.MA",
    category_name: "Joint Incident Response",
    risk_title: "Хамтарсан хариу үйлдлийн журамгүй",
    vulnerability_description:
      "Vendor-ийн орчинд гарсан кибер аюулт явдалд хамтран хариу үйлдэх playbook, харилцах сувгууд тодорхойгүй.",
    subject_types: ["vendor", "process"],
  },
  {
    function_code: "RC",
    function_mn: "Сэргээх",
    category_code: "RC.RP",
    category_name: "Vendor Dependency Recovery",
    risk_title: "Чухал үйлчилгээ үзүүлэгчид орлуулах хувилбаргүй",
    vulnerability_description:
      "Single point of failure болсон vendor доголдсон тохиолдолд орлуулах үйлчлэгч, шилжих төлөвлөгөө байхгүй.",
    subject_types: ["vendor"],
  },

  // ── POLICY-based ────────────────────────────────────────────────────────
  {
    function_code: "GV",
    function_mn: "Засаглал",
    category_code: "GV.RM",
    category_name: "Risk Management Strategy",
    risk_title: "Эрсдэлийн удирдлагын бодлого байхгүй",
    vulnerability_description:
      "Байгууллагад кибер эрсдэлийн удирдлагын албан ёсны бодлого, журам байхгүй.",
    subject_types: ["policy"],
  },
  {
    function_code: "GV",
    function_mn: "Засаглал",
    category_code: "GV.PO",
    category_name: "Policy",
    risk_title: "Хуучирсан мэдээллийн аюулгүй байдлын бодлого",
    vulnerability_description:
      "Бодлого 12 сараас дээш хугацаагаар шинэчлэгдээгүй, одоогийн орчинтой нийцэхгүй байна.",
    subject_types: ["policy"],
  },
  {
    function_code: "PR",
    function_mn: "Хамгаалах",
    category_code: "PR.AA",
    category_name: "Identity & Access Control",
    risk_title: "Хандалтын эрхийн зохисгүй удирдлага",
    vulnerability_description:
      "Хэрэглэгчийн хандалтын эрх хяналтгүй, хуучирсан хандалтын эрх идэвхтэй байна.",
    subject_types: ["policy", "personnel"],
  },
  {
    function_code: "RS",
    function_mn: "Хариу үйлдэл",
    category_code: "RS.CO",
    category_name: "Communication",
    risk_title: "Аюулт явдлын мэдэгдлийн журамгүй",
    vulnerability_description:
      "Аюулт явдал гарсан үед хэн нэгэнд хэзээ мэдэгдэх талаар тодорхой журам байхгүй.",
    subject_types: ["policy", "process"],
  },

  // ── PERSONNEL-based ─────────────────────────────────────────────────────
  {
    function_code: "PR",
    function_mn: "Хамгаалах",
    category_code: "PR.AT",
    category_name: "Awareness & Training",
    risk_title: "Мэдлэг дутмаглал - Фишинг халдлага",
    vulnerability_description:
      "Ажилтнуудын кибер аюулгүй байдлын сургалт хангалтгүй, фишинг халдлагад өртөх магадлал өндөр.",
    subject_types: ["personnel"],
  },
  {
    function_code: "GV",
    function_mn: "Засаглал",
    category_code: "GV.RR",
    category_name: "Roles & Responsibilities",
    risk_title: "Үүрэг хариуцлага тодорхой бус",
    vulnerability_description:
      "Кибер аюулгүй байдлын үүрэг ажилтнуудын хооронд хуваарилагдаагүй, хариуцагчгүй.",
    subject_types: ["personnel", "policy"],
  },
  {
    function_code: "PR",
    function_mn: "Хамгаалах",
    category_code: "PR.AA",
    category_name: "Insider Threat",
    risk_title: "Эрх бүхий хэрэглэгчийн доромж үйлдэл",
    vulnerability_description:
      "Privileged эрхтэй ажилтны үйлдэл нь хяналтгүй, дотоод аюулт халдлагад өртөх эрсдэлтэй.",
    subject_types: ["personnel"],
  },

  // ── LOCATION / PHYSICAL ─────────────────────────────────────────────────
  {
    function_code: "PR",
    function_mn: "Хамгаалах",
    category_code: "PR.IR",
    category_name: "Infrastructure Resilience",
    risk_title: "Цахилгаан тасалдах эрсдэл",
    vulnerability_description:
      "Серверийн өрөөнд UPS / генератор байхгүй буюу тогтмол шалгагдахгүй.",
    subject_types: ["location"],
  },
  {
    function_code: "PR",
    function_mn: "Хамгаалах",
    category_code: "PR.IR",
    category_name: "Physical Access",
    risk_title: "Физик хандалтын хяналт сул",
    vulnerability_description:
      "Серверийн өрөө, дата төв рүү орох эрх хяналтгүй, бүртгэлгүй.",
    subject_types: ["location"],
  },
  {
    function_code: "RC",
    function_mn: "Сэргээх",
    category_code: "RC.RP",
    category_name: "Disaster Recovery",
    risk_title: "Гамшгийн үед сэргээх төлөвлөгөө байхгүй",
    vulnerability_description:
      "Гал, үер, газар хөдлөлт зэрэг бодит гамшгийн үеийн ажиллах төлөвлөгөө боловсруулагдаагүй.",
    subject_types: ["location", "process"],
  },
  // ── COMPLIANCE / REGULATORY ─────────────────────────────────────────────
  {
    function_code: "GV",
    function_mn: "Засаглал",
    category_code: "GV.OC",
    category_name: "Organizational Context",
    risk_title: "Хууль зүйн шаардлага мэдэгдэхгүй",
    vulnerability_description:
      "Байгууллагад үйлчлэх хууль, зохицуулалт (хувийн мэдээлэл, санхүү гэх мэт) тодорхойгүй.",
    subject_types: ["compliance"],
  },
  {
    function_code: "GV",
    function_mn: "Засаглал",
    category_code: "GV.OC",
    category_name: "Privacy Compliance",
    risk_title: "Хувийн мэдээлэл хамгаалах хуулийн зөрчил",
    vulnerability_description:
      "Хэрэглэгчийн зөвшөөрөлгүйгээр мэдээлэл цуглуулдаг, хадгалдаг буюу гуравдагч этгээдтэй хуваалцдаг.",
    subject_types: ["compliance"],
  },
  {
    function_code: "RS",
    function_mn: "Хариу үйлдэл",
    category_code: "RS.CO",
    category_name: "Regulatory Notification",
    risk_title: "Зохицуулагч байгууллагад мэдэгдэх журамгүй",
    vulnerability_description:
      "Мэдээлэл алдагдсан тохиолдолд хууль ёсны хугацаанд зохицуулагч / хэрэглэгчдэд мэдэгдэх төлөвлөгөөгүй.",
    subject_types: ["compliance", "process"],
  },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function calcLevel(score: number): RiskLevel {
  if (score <= 4) return "Low";
  if (score <= 9) return "Medium";
  if (score <= 16) return "High";
  return "Critical";
}

function calcResidualRisk(
  inherentScore: number,
  selectedControlIds: string[],
  effectiveness: Record<string, number>,
): { score: number; level: RiskLevel } {
  if (selectedControlIds.length === 0) {
    return { score: inherentScore, level: calcLevel(inherentScore) };
  }
  const values = selectedControlIds.map((id) => effectiveness[id] ?? 0);
  const avg = values.reduce((a, b) => a + b, 0) / values.length;
  const score = Math.max(1, Math.round(inherentScore * (1 - avg / 100)));
  return { score, level: calcLevel(score) };
}

function levelEmoji(level: string) {
  if (level === "Critical") return "🔴";
  if (level === "High") return "🟠";
  if (level === "Medium") return "🟡";
  if (level === "Low") return "🟢";
  return "⚪";
}

function riskWeight(level: string | null | undefined) {
  if (level === "Critical") return 4;
  if (level === "High") return 3;
  if (level === "Medium") return 2;
  if (level === "Low") return 1;
  return 0;
}

const NIST_FUNCTION_LABELS: Record<string, string> = {
  GV: "Засаглал",
  ID: "Таних",
  PR: "Хамгаалах",
  DE: "Илрүүлэх",
  RS: "Хариу арга хэмжээ",
  RC: "Сэргээх",
};

const NIST_FUNCTION_ALIASES: Record<string, string> = {
  GOVERN: "GV",
  GOVERNANCE: "GV",
  GV: "GV",
  ЗАСАГЛАЛ: "GV",
  IDENTIFY: "ID",
  ID: "ID",
  ТАНИХ: "ID",
  PROTECT: "PR",
  PR: "PR",
  ХАМГААЛАХ: "PR",
  DETECT: "DE",
  DE: "DE",
  ИЛРҮҮЛЭХ: "DE",
  RESPOND: "RS",
  RS: "RS",
  "ХАРИУ ҮЙЛДЭЛ": "RS",
  "ХАРИУ АРГА ХЭМЖЭЭ": "RS",
  RECOVER: "RC",
  RC: "RC",
  СЭРГЭЭХ: "RC",
};

function nistFunctionCode(
  value: string | null | undefined,
  category?: string | null,
) {
  const categoryPrefix = (category ?? "").split(".")[0]?.toUpperCase();
  if (categoryPrefix && NIST_FUNCTION_LABELS[categoryPrefix]) {
    return categoryPrefix;
  }

  const normalized = (value ?? "").trim().toUpperCase();
  return NIST_FUNCTION_ALIASES[normalized] ?? "";
}

function nistFunctionDisplay(
  value: string | null | undefined,
  category?: string | null,
) {
  const code = nistFunctionCode(value, category);
  if (!code) return (value ?? "").trim() || "Тодорхойгүй";
  return `${NIST_FUNCTION_LABELS[code]} (${code})`;
}

function controlMatchesRisk(control: NistControlOption, risk: WizardRisk) {
  const riskCategory = (risk.nist_csf_category || risk.nist_category || "")
    .trim()
    .toUpperCase();
  const controlCategory = (control.nist_csf_category ?? "")
    .trim()
    .toUpperCase();
  const exactCategoryMatch =
    Boolean(riskCategory && controlCategory) &&
    (riskCategory === controlCategory ||
      riskCategory.startsWith(`${controlCategory}.`) ||
      controlCategory.startsWith(`${riskCategory}.`));

  if (exactCategoryMatch) return true;

  const riskFunction = nistFunctionCode(risk.nist_csf_function, riskCategory);
  const controlFunction = nistFunctionCode(
    control.nist_csf_function,
    controlCategory,
  );
  return Boolean(
    riskFunction && controlFunction && riskFunction === controlFunction,
  );
}

function controlSortRank(
  control: NistControlOption,
  risk: WizardRisk,
  selectedIds: Set<string>,
) {
  if (selectedIds.has(control.control_id)) return -1;
  const riskCategory = (risk.nist_csf_category || risk.nist_category || "")
    .trim()
    .toUpperCase();
  const controlCategory = (control.nist_csf_category ?? "")
    .trim()
    .toUpperCase();
  if (riskCategory && controlCategory && riskCategory === controlCategory) {
    return 0;
  }
  if (controlMatchesRisk(control, risk)) return 1;
  return 2;
}

function controlOptionsForRisk(
  controls: NistControlOption[],
  risk: WizardRisk,
) {
  const selectedIds = new Set(risk.selected_control_ids ?? []);
  const riskCategory = (risk.nist_csf_category || risk.nist_category || "")
    .trim()
    .toUpperCase();

  // Prefer exact category matches; only use function-level fallback if none exist
  const exactMatches = controls.filter((control) => {
    const controlCategory = (control.nist_csf_category ?? "")
      .trim()
      .toUpperCase();
    return (
      Boolean(riskCategory && controlCategory) &&
      (riskCategory === controlCategory ||
        riskCategory.startsWith(`${controlCategory}.`) ||
        controlCategory.startsWith(`${riskCategory}.`))
    );
  });

  const base =
    exactMatches.length > 0
      ? exactMatches
      : controls.filter((control) => controlMatchesRisk(control, risk));

  const ordered = [...base].sort((a, b) => {
    const rankDiff =
      controlSortRank(a, risk, selectedIds) -
      controlSortRank(b, risk, selectedIds);
    if (rankDiff !== 0) return rankDiff;
    const priorityDiff = (a.priority ?? 99) - (b.priority ?? 99);
    if (priorityDiff !== 0) return priorityDiff;
    return a.control_id.localeCompare(b.control_id);
  });

  const visible = new Map<string, NistControlOption>();
  controls
    .filter((control) => selectedIds.has(control.control_id))
    .forEach((control) => visible.set(control.control_id, control));
  ordered.forEach((control) => visible.set(control.control_id, control));

  return Array.from(visible.values());
}

function highestRiskLevel(threats: ThreatOption[]) {
  return threats.reduce(
    (current, threat) =>
      riskWeight(threat.risk_level) > riskWeight(current)
        ? (threat.risk_level ?? current)
        : current,
    "Unknown",
  );
}

function filterMappingsToVisibleThreats(
  mappings: AssetThreatMapping[],
  vulnerabilities: VulnerabilityOption[],
  savedRisks: SavedRisk[] = [],
) {
  const visiblePairs = new Set(
    vulnerabilities
      .filter((v) => v.asset_id != null && v.threat_id != null)
      .map((v) => `${v.asset_id}-${v.threat_id}`),
  );
  const registeredPairs = new Set(
    savedRisks
      .filter(
        (risk) =>
          risk.asset_id != null &&
          risk.threat_id != null &&
          risk.status !== "Closed",
      )
      .map((risk) => `${risk.asset_id}-${risk.threat_id}`),
  );

  return mappings
    .map((asset) => {
      const threats = asset.threats.filter((threat) => {
        const pairKey = `${asset.asset_id}-${threat.id}`;
        return visiblePairs.has(pairKey) && !registeredPairs.has(pairKey);
      });
      return {
        ...asset,
        mapped_threat_count: threats.length,
        highest_risk: highestRiskLevel(threats),
        threats,
      };
    })
    .filter((asset) => asset.threats.length > 0);
}

function uid() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
}

// ─── Step Indicator ───────────────────────────────────────────────────────────

function StepIndicator({
  current,
  onNavigate,
}: {
  current: number;
  onNavigate: (s: number) => void;
}) {
  return (
    <div className="grid w-full grid-cols-7 gap-1.5">
      {STEPS.map((step, i) => {
        const n = i + 1;
        const done = n < current;
        const active = n === current;
        return (
          <div key={n} className="min-w-0">
            <button
              type="button"
              onClick={() => onNavigate(n)}
              className={`flex min-h-10 w-full items-center gap-1.5 rounded-lg px-2 py-1.5 text-left transition-colors ${
                active
                  ? "bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-950"
                  : done
                    ? "bg-emerald-600 text-white shadow-sm hover:bg-emerald-700 dark:bg-emerald-500 dark:text-white"
                    : "text-muted-foreground hover:bg-muted"
              }`}
            >
              <span
                className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[11px] font-bold ${
                  active
                    ? "bg-white text-slate-950 dark:bg-slate-950 dark:text-white"
                    : done
                      ? "bg-white text-emerald-700 dark:bg-white dark:text-emerald-700"
                      : "bg-muted text-muted-foreground"
                }`}
              >
                {done ? <CheckCircle2 className="h-3.5 w-3.5" /> : n}
              </span>
              <div className="hidden min-w-0 sm:block">
                <p className="truncate text-[11px] font-semibold leading-tight">
                  {step.label}
                </p>
                <p
                  className={`truncate text-[9px] leading-tight ${
                    active
                      ? "text-white/70 dark:text-slate-950/70"
                      : done
                        ? "text-white/85"
                        : "text-muted-foreground"
                  }`}
                >
                  {step.sublabel}
                </p>
              </div>
            </button>
          </div>
        );
      })}
    </div>
  );
}

// ─── Step 1: Object Selection ─────────────────────────────────────────────────

function Step1Method({
  subjectType,
  onSubjectChange,
}: {
  subjectType: SubjectType;
  onSubjectChange: (s: SubjectType) => void;
}) {
  const subjectOrder: SubjectType[] = [
    "asset",
    "process",
    "vendor",
    "policy",
    "personnel",
    "location",
    "compliance",
  ];

  return (
    <div>
      <div className="mb-4">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-xl font-bold">Хөрөнгө сонгох</h2>
          <span className="rounded-full bg-slate-100 px-2 py-0.5 text-[10px] font-semibold text-slate-600 dark:bg-slate-800 dark:text-slate-300">
            Алхам 1
          </span>
        </div>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-7">
        {subjectOrder.map((key) => {
          const meta = SUBJECT_META[key];
          const Icon = meta.icon;
          const active = subjectType === key;
          return (
            <button
              key={key}
              type="button"
              onClick={() => onSubjectChange(key)}
              className={`relative rounded-xl border p-3 text-left transition-all ${
                active
                  ? `${meta.ring} ring-2`
                  : "border-slate-200 bg-white hover:border-slate-300 dark:border-slate-800 dark:bg-slate-950 dark:hover:border-slate-700"
              }`}
            >
              {active && (
                <span
                  className={`absolute right-1.5 top-1.5 flex h-5 w-5 items-center justify-center rounded-full ${meta.color} text-white`}
                >
                  <CheckCircle2 className="h-3 w-3" />
                </span>
              )}
              <div
                className={`mb-2 flex h-9 w-9 items-center justify-center rounded-lg ${
                  active ? meta.color : "bg-slate-100 dark:bg-slate-800"
                }`}
              >
                <Icon
                  className={`h-5 w-5 ${
                    active ? "text-white" : "text-slate-700 dark:text-slate-300"
                  }`}
                />
              </div>
              <p className="text-xs font-bold leading-tight">{meta.mn}</p>
              <p className="mt-0.5 text-[10px] text-muted-foreground leading-tight line-clamp-2">
                {meta.desc}
              </p>
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ─── Step 2: Connect Threats ──────────────────────────────────────────────────

function Step2AssetThreat({
  mappings,
  selected,
  onToggle,
  loading,
}: {
  mappings: AssetThreatMapping[];
  selected: Set<string>;
  onToggle: (key: string) => void;
  loading: boolean;
}) {
  const [expandedAssets, setExpandedAssets] = useState<Set<number>>(new Set());
  const [search, setSearch] = useState("");

  function toggleAsset(id: number) {
    setExpandedAssets((prev) => {
      const s = new Set(prev);
      if (s.has(id)) {
        s.delete(id);
      } else {
        s.add(id);
      }
      return s;
    });
  }

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    if (!q) return mappings;
    return mappings.filter(
      (m) =>
        m.asset_name.toLowerCase().includes(q) ||
        (m.asset_type ?? "").toLowerCase().includes(q) ||
        m.threats.some((t) => t.threat_name.toLowerCase().includes(q)),
    );
  }, [mappings, search]);

  if (loading)
    return (
      <div className="flex h-40 items-center justify-center">
        <div className="h-6 w-6 animate-spin rounded-full border-4 border-slate-200 border-t-slate-700" />
      </div>
    );

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-xl font-bold">Хөрөнгөд хамаарах эрсдэл сонгох</h2>
      </div>
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Хөрөнгө эсвэл аюулаар хайх…"
            className="pl-8"
          />
          <SlidersHorizontal className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
        </div>
        <span className="shrink-0 text-sm text-muted-foreground">
          <span className="font-semibold text-slate-950 dark:text-slate-50">
            {selected.size}
          </span>{" "}
          хос сонгогдсон
        </span>
      </div>
      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-xl border border-dashed py-16">
          <Database className="mb-3 h-10 w-10 text-muted-foreground/40" />
          <p className="text-sm text-muted-foreground">
            Threats хуудсанд харагдаж буй хөрөнгө-аюулын холбоо олдсонгүй.
            Эхлээд Threats хуудсанд scan хийж эмзэг байдлыг шинэчилнэ үү.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((asset) => {
            const expanded = expandedAssets.has(asset.asset_id);
            const selectedCount = asset.threats.filter((t) =>
              selected.has(`${asset.asset_id}-${t.id}`),
            ).length;
            return (
              <div
                key={asset.asset_id}
                className="overflow-hidden rounded-xl border dark:border-slate-800"
              >
                <div
                  className="flex cursor-pointer items-center gap-3 px-4 py-3 hover:bg-muted/40"
                  onClick={() => toggleAsset(asset.asset_id)}
                >
                  <div
                    className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-100 dark:bg-slate-800`}
                  >
                    <Database className="h-4 w-4 text-slate-600 dark:text-slate-300" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-semibold">
                        {asset.asset_name}
                      </span>
                      {asset.asset_type && (
                        <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] text-slate-600 dark:bg-slate-800 dark:text-slate-400">
                          {asset.asset_type}
                        </span>
                      )}
                      {asset.internet_exposed && (
                        <span className="flex items-center gap-0.5 rounded-full border border-orange-200 bg-orange-50 px-2 py-0.5 text-[10px] font-medium text-orange-700 dark:border-orange-800 dark:bg-orange-950/30">
                          <Globe2 className="h-2.5 w-2.5" />
                          Internet
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {asset.threats.length} аюул холбогдсон ·{" "}
                      {selectedCount > 0 && (
                        <span className="font-medium text-emerald-600">
                          {selectedCount} сонгогдсон
                        </span>
                      )}
                    </p>
                  </div>
                  <span
                    className={`shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-semibold ${LEVEL_STYLE[asset.highest_risk] ?? LEVEL_STYLE.Unknown}`}
                  >
                    {levelEmoji(asset.highest_risk)} {asset.highest_risk}
                  </span>
                  {expanded ? (
                    <ChevronUp className="h-4 w-4 shrink-0 text-muted-foreground" />
                  ) : (
                    <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
                  )}
                </div>
                {expanded && (
                  <div className="border-t dark:border-slate-800">
                    <div className="flex items-center justify-between border-b bg-muted/30 px-4 py-1.5 dark:border-slate-800">
                      <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wide">
                        Аюулууд
                      </span>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          const allSelected = asset.threats.every((t) =>
                            selected.has(`${asset.asset_id}-${t.id}`),
                          );
                          asset.threats.forEach((t) =>
                            onToggle(`${asset.asset_id}-${t.id}`),
                          );
                          void allSelected;
                        }}
                        className="text-[11px] font-medium text-sky-600 hover:underline dark:text-sky-400"
                      >
                        Бүгдийг сонгох
                      </button>
                    </div>
                    <div className="divide-y dark:divide-slate-800">
                      {asset.threats.map((threat) => {
                        const key = `${asset.asset_id}-${threat.id}`;
                        const isSelected = selected.has(key);
                        return (
                          <div
                            key={threat.id}
                            className={`flex cursor-pointer items-start gap-3 px-4 py-3 transition-colors ${isSelected ? "bg-emerald-50/50 dark:bg-emerald-950/10" : "hover:bg-muted/30"}`}
                            onClick={() => onToggle(key)}
                          >
                            <div
                              className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded border ${isSelected ? "border-emerald-500 bg-emerald-500" : "border-slate-300 dark:border-slate-600"}`}
                            >
                              {isSelected && (
                                <CheckCircle2 className="h-3.5 w-3.5 text-white" />
                              )}
                            </div>
                            <div className="min-w-0 flex-1">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="text-sm font-medium">
                                  {threat.threat_name}
                                </span>
                                {threat.threat_type && (
                                  <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] text-slate-600 dark:bg-slate-800 dark:text-slate-400">
                                    {threat.threat_type}
                                  </span>
                                )}
                              </div>
                              {threat.description && (
                                <p className="mt-0.5 text-xs text-muted-foreground line-clamp-2">
                                  {threat.description}
                                </p>
                              )}
                            </div>
                            <span
                              className={`shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-semibold ${LEVEL_STYLE[threat.risk_level ?? "Unknown"] ?? LEVEL_STYLE.Unknown}`}
                            >
                              {threat.risk_level ?? "Unknown"}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function Step2Framework({
  subjectType,
  selectedKeys,
  onToggle,
  savedRisks,
}: {
  subjectType: SubjectType;
  selectedKeys: Set<string>;
  onToggle: (key: string) => void;
  savedRisks: SavedRisk[];
}) {
  const [expandedFns, setExpandedFns] = useState<Set<string>>(
    new Set(["GV", "ID", "PR"]),
  );
  const FN_META: Record<string, { mn: string; color: string }> = {
    GV: { mn: "Засаглал", color: "bg-violet-500" },
    ID: { mn: "Таних", color: "bg-sky-500" },
    PR: { mn: "Хамгаалах", color: "bg-emerald-500" },
    DE: { mn: "Илрүүлэх", color: "bg-amber-500" },
    RS: { mn: "Хариу үйлдэл", color: "bg-rose-500" },
    RC: { mn: "Сэргээх", color: "bg-lime-500" },
  };
  const subjectMeta = SUBJECT_META[subjectType];

  const savedFrameworkKeys = useMemo(
    () =>
      new Set(
        savedRisks
          .filter((s) => !s.asset_id && !s.threat_id && s.status !== "Closed")
          .map((s) => `${s.risk_title}__${s.nist_csf_category ?? ""}`),
      ),
    [savedRisks],
  );

  const filteredRisks = FRAMEWORK_RISKS.filter(
    (r) =>
      r.subject_types.includes(subjectType) &&
      !savedFrameworkKeys.has(`${r.risk_title}__${r.category_code}`),
  );
  const byFunction = filteredRisks.reduce(
    (acc, r) => {
      if (!acc[r.function_code]) acc[r.function_code] = [];
      acc[r.function_code].push(r);
      return acc;
    },
    {} as Record<string, typeof FRAMEWORK_RISKS>,
  );

  function toggleFn(fn: string) {
    setExpandedFns((prev) => {
      const s = new Set(prev);
      if (s.has(fn)) {
        s.delete(fn);
      } else {
        s.add(fn);
      }
      return s;
    });
  }

  return (
    <div className="space-y-5">
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-xl font-bold">
            NIST CSF суурилсан эрсдэлийн жагсаалт
          </h2>
          <span
            className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${subjectMeta.badge}`}
          >
            <subjectMeta.icon className="h-3 w-3" />
            {subjectMeta.mn}
          </span>
        </div>
      </div>
      {filteredRisks.length === 0 && (
        <div className="flex flex-col items-center justify-center rounded-xl border border-dashed py-12">
          <BookOpen className="mb-3 h-10 w-10 text-muted-foreground/40" />
          <p className="text-sm text-muted-foreground">
            «{subjectMeta.mn}» хөрөнгөд тохирох стандарт загвар олдсонгүй.
          </p>
        </div>
      )}
      <div className="space-y-2">
        {Object.entries(byFunction).map(([fn, items]) => {
          const meta = FN_META[fn] ?? { mn: fn, color: "bg-slate-500" };
          const expanded = expandedFns.has(fn);
          const selectedInFn = items.filter((item) => {
            const key = `fw-${item.category_code}-${item.risk_title.slice(0, 20)}`;
            return selectedKeys.has(key);
          }).length;
          return (
            <div
              key={fn}
              className="overflow-hidden rounded-xl border dark:border-slate-800"
            >
              <button
                type="button"
                onClick={() => toggleFn(fn)}
                className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-muted/40"
              >
                <div
                  className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg ${meta.color}`}
                >
                  <span className="text-xs font-bold text-white">{fn}</span>
                </div>
                <span className="flex-1 text-sm font-semibold">{meta.mn}</span>
                {selectedInFn > 0 && (
                  <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-[10px] font-semibold text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300">
                    {selectedInFn} сонгогдсон
                  </span>
                )}
                {expanded ? (
                  <ChevronUp className="h-4 w-4 text-muted-foreground" />
                ) : (
                  <ChevronDown className="h-4 w-4 text-muted-foreground" />
                )}
              </button>
              {expanded && (
                <div className="divide-y border-t dark:divide-slate-800 dark:border-slate-800">
                  {items.map((item) => {
                    const key = `fw-${item.category_code}-${item.risk_title.slice(0, 20)}`;
                    const isSelected = selectedKeys.has(key);
                    return (
                      <div
                        key={key}
                        className={`flex cursor-pointer items-start gap-3 px-4 py-3 transition-colors ${isSelected ? "bg-emerald-50/50 dark:bg-emerald-950/10" : "hover:bg-muted/30"}`}
                        onClick={() => onToggle(key)}
                      >
                        <div
                          className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded border ${isSelected ? "border-emerald-500 bg-emerald-500" : "border-slate-300 dark:border-slate-600"}`}
                        >
                          {isSelected && (
                            <CheckCircle2 className="h-3.5 w-3.5 text-white" />
                          )}
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] font-bold text-slate-600 dark:bg-slate-800 dark:text-slate-400">
                              {item.category_code}
                            </span>
                            <span className="text-sm font-medium">
                              {item.risk_title}
                            </span>
                          </div>
                          <p className="mt-0.5 text-xs text-muted-foreground line-clamp-2">
                            {item.vulnerability_description}
                          </p>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Step 3: Vulnerabilities & Controls ──────────────────────────────────────

function Step3Vuln({
  risks,
  onChange,
}: {
  risks: WizardRisk[];
  onChange: (key: string, field: keyof WizardRisk, value: string) => void;
}) {
  const [expanded, setExpanded] = useState<Set<string>>(
    new Set(risks.slice(0, 3).map((r) => r.key)),
  );

  function toggleCard(key: string) {
    setExpanded((prev) => {
      const s = new Set(prev);
      if (s.has(key)) {
        s.delete(key);
      } else {
        s.add(key);
      }
      return s;
    });
  }

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-xl font-bold">Эмзэг байдлын тайлбар</h2>
      </div>
      <div className="space-y-2">
        {risks.map((r, i) => {
          const isExpanded = expanded.has(r.key);
          const csfCategory =
            r.nist_csf_category || r.nist_category || "Тодорхойгүй";
          const csfFunction = nistFunctionDisplay(
            r.nist_csf_function,
            csfCategory,
          );
          return (
            <div
              key={r.key}
              className="overflow-hidden rounded-xl border dark:border-slate-800"
            >
              <div
                className="flex cursor-pointer items-center gap-3 px-4 py-3 hover:bg-muted/40"
                onClick={() => toggleCard(r.key)}
              >
                <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-slate-100 text-xs font-bold text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                  {i + 1}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold truncate">
                    {r.risk_title}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {r.asset_name} → {r.threat_name}
                  </p>
                  <div className="mt-1 flex flex-wrap gap-1.5">
                    <span className="rounded-full border border-sky-200 bg-sky-50 px-2 py-0.5 text-[10px] font-semibold text-sky-700 dark:border-sky-900 dark:bg-sky-950/40 dark:text-sky-300">
                      {csfFunction}
                    </span>
                    <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[10px] font-semibold text-slate-600 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300">
                      {csfCategory}
                    </span>
                  </div>
                </div>
                {r.vulnerability_description && (
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
                )}
                {isExpanded ? (
                  <ChevronUp className="h-4 w-4 shrink-0 text-muted-foreground" />
                ) : (
                  <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
                )}
              </div>
              {isExpanded && (
                <div className="border-t px-4 py-4 dark:border-slate-800">
                  <div className="mb-4 flex gap-3 rounded-lg border border-sky-100 bg-sky-50/70 p-3 text-sm dark:border-sky-900 dark:bg-sky-950/20">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-white text-sky-600 shadow-sm dark:bg-slate-950 dark:text-sky-300">
                      <BookOpen className="h-4 w-4" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-semibold uppercase tracking-wide text-sky-700 dark:text-sky-300">
                        Холбогдох NIST CSF
                      </p>
                      <p className="mt-1 text-sm font-semibold text-slate-900 dark:text-slate-100">
                        {csfFunction} · {csfCategory}
                      </p>
                      <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
                        Энэ ангилал нь сонгосон эрсдэлээс автоматаар
                        тодорхойлогдоно.
                      </p>
                    </div>
                  </div>
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div className="sm:col-span-2">
                      <label className="mb-1 block text-xs font-medium">
                        Эмзэг байдлын тайлбар
                      </label>
                      <Textarea
                        value={r.vulnerability_description}
                        onChange={(e) =>
                          onChange(
                            r.key,
                            "vulnerability_description",
                            e.target.value,
                          )
                        }
                        rows={3}
                        placeholder="Ямар эмзэг байдал байна вэ? Жнь: Нууц үг дангаараа ашигладаг, MFA байхгүй..."
                        className="resize-y text-sm"
                      />
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Step 5: Control Selection ────────────────────────────────────────────────

function Step5Controls({
  risks,
  controls,
  onToggleControl,
  onCustomControlsChange,
}: {
  risks: WizardRisk[];
  controls: NistControlOption[];
  onToggleControl: (key: string, controlId: string) => void;
  onCustomControlsChange: (key: string, value: string) => void;
}) {
  const [expanded, setExpanded] = useState<Set<string>>(
    new Set(risks.slice(0, 3).map((r) => r.key)),
  );
  const [controlSearch, setControlSearch] = useState("");
  const normalizedControlSearch = controlSearch.trim().toLowerCase();

  function toggleCard(key: string) {
    setExpanded((prev) => {
      const s = new Set(prev);
      if (s.has(key)) s.delete(key);
      else s.add(key);
      return s;
    });
  }

  function matchesControlSearch(control: NistControlOption) {
    if (!normalizedControlSearch) return true;
    return [
      control.control_id,
      control.control_name,
      control.domain,
      control.description,
      control.nist_csf_function,
      control.nist_csf_category,
    ].some((value) =>
      (value ?? "").toLowerCase().includes(normalizedControlSearch),
    );
  }

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-xl font-bold">Одоогийн хяналт сонгох</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Эрсдэлийг бууруулах хяналтын мэдээллийг оруулна уу.
        </p>
        <div className="relative mt-3 max-w-xl">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={controlSearch}
            onChange={(e) => setControlSearch(e.target.value)}
            placeholder="Хяналтын ID, нэр, тайлбараар хайх..."
            className="pl-9"
          />
        </div>
      </div>
      <div className="space-y-2">
        {risks.map((r, i) => {
          const isExpanded = expanded.has(r.key);
          const selectedIds = r.selected_control_ids ?? [];
          const nistCount = selectedIds.filter(
            (id) => id !== "__custom__",
          ).length;
          const hasCustom = Boolean(r.custom_controls?.trim());
          const displayedControls = controlOptionsForRisk(controls, r);
          const filteredControls =
            displayedControls.filter(matchesControlSearch);
          const csfCategory =
            r.nist_csf_category || r.nist_category || "Тодорхойгүй";
          const csfFunction = nistFunctionDisplay(
            r.nist_csf_function,
            csfCategory,
          );
          return (
            <div
              key={r.key}
              className="overflow-hidden rounded-xl border dark:border-slate-800"
            >
              <div
                className="flex cursor-pointer items-center gap-3 px-4 py-3 hover:bg-muted/40"
                onClick={() => toggleCard(r.key)}
              >
                <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-slate-100 text-xs font-bold text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                  {i + 1}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-semibold">
                    {r.risk_title}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {r.asset_name} → {r.threat_name}
                  </p>
                  <div className="mt-1 flex flex-wrap gap-1.5">
                    <span className="rounded-full border border-sky-200 bg-sky-50 px-2 py-0.5 text-[10px] font-semibold text-sky-700 dark:border-sky-900 dark:bg-sky-950/40 dark:text-sky-300">
                      {csfFunction}
                    </span>
                    <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[10px] font-semibold text-slate-600 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300">
                      {csfCategory}
                    </span>
                  </div>
                </div>
                <span className="shrink-0 rounded-full bg-emerald-100 px-2 py-0.5 text-[11px] font-semibold text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300">
                  {nistCount} NIST{hasCustom ? " + бусад" : ""}
                </span>
                {isExpanded ? (
                  <ChevronUp className="h-4 w-4 shrink-0 text-muted-foreground" />
                ) : (
                  <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
                )}
              </div>
              {isExpanded && (
                <div className="border-t px-4 py-4 dark:border-slate-800">
                  <div className="mb-3 flex items-center gap-2 flex-wrap">
                    <ShieldCheck className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
                    <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                      NIST SP 800-53 хяналтууд
                    </span>
                    {csfCategory && csfCategory !== "Тодорхойгүй" && (
                      <span className="rounded-full border border-sky-200 bg-sky-50 px-2 py-0.5 text-[10px] font-semibold text-sky-700 dark:border-sky-900 dark:bg-sky-950/40 dark:text-sky-300">
                        {csfCategory}-д тохирох
                      </span>
                    )}
                    <span className="ml-auto shrink-0 rounded-full bg-emerald-100 px-2 py-0.5 text-[11px] font-semibold text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300">
                      {nistCount} сонгогдсон
                    </span>
                    {normalizedControlSearch && (
                      <span className="shrink-0 rounded-full bg-blue-100 px-2 py-0.5 text-[11px] font-semibold text-blue-700 dark:bg-blue-950/40 dark:text-blue-300">
                        {filteredControls.length}/{displayedControls.length}{" "}
                        олдсон
                      </span>
                    )}
                  </div>
                  {filteredControls.length > 0 ? (
                    <div className="max-h-72 space-y-1.5 overflow-y-auto pr-1">
                      {filteredControls.map((control) => {
                        const isSelected = selectedIds.includes(
                          control.control_id,
                        );
                        return (
                          <label
                            key={control.control_id}
                            className={`flex cursor-pointer items-start gap-2 rounded-md border px-2 py-2 text-xs transition-colors ${
                              isSelected
                                ? "border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-200"
                                : "border-slate-200 bg-white hover:border-slate-300 dark:border-slate-800 dark:bg-slate-950 dark:hover:border-slate-700"
                            }`}
                          >
                            <input
                              type="checkbox"
                              checked={isSelected}
                              onChange={() =>
                                onToggleControl(r.key, control.control_id)
                              }
                              className="mt-0.5 h-3.5 w-3.5 shrink-0 rounded border-slate-300 text-emerald-600"
                            />
                            <div className="min-w-0 flex-1 space-y-1">
                              <div className="flex flex-wrap items-center gap-1.5">
                                <span className="shrink-0 rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] font-bold text-slate-700 dark:bg-slate-800 dark:text-slate-200">
                                  {control.control_id}
                                </span>
                                <span className="font-medium">
                                  {control.control_name ?? "Нэргүй хяналт"}
                                </span>
                                {control.domain && (
                                  <span className="rounded-full bg-slate-50 px-1.5 py-0.5 text-[10px] text-slate-500 dark:bg-slate-900 dark:text-slate-400">
                                    {control.domain}
                                  </span>
                                )}
                              </div>
                              {control.description && (
                                <p
                                  className="line-clamp-2 text-[11px] leading-snug text-muted-foreground"
                                  title={control.description}
                                >
                                  {control.description}
                                </p>
                              )}
                            </div>
                          </label>
                        );
                      })}
                    </div>
                  ) : (
                    <p className="rounded-md border border-dashed bg-white px-3 py-3 text-center text-xs text-muted-foreground dark:border-slate-800 dark:bg-slate-950">
                      {controls.length === 0
                        ? "NIST SP 800-53 хяналтын сан ачаалагдаагүй байна."
                        : normalizedControlSearch
                          ? "Хайлтад тохирох хяналт олдсонгүй."
                          : "Энэ эрсдэлд тохирох хяналт олдсонгүй."}
                    </p>
                  )}

                  {/* ── Custom / other controls ── */}
                  <div className="mt-4 border-t pt-4 dark:border-slate-800">
                    <label className="mb-1.5 flex items-center gap-2 text-xs font-semibold text-muted-foreground uppercase tracking-wide">
                      <BookOpen className="h-3.5 w-3.5 text-amber-500" />
                      Бусад хяналт (заавал биш)
                    </label>
                    <Textarea
                      value={r.custom_controls ?? ""}
                      onChange={(e) =>
                        onCustomControlsChange(r.key, e.target.value)
                      }
                      rows={2}
                      placeholder="NIST жагсаалтад байхгүй, одоогоор хэрэгжүүлсэн бусад хяналт, арга хэмжээг энд тайлбарлана уу…"
                      className="resize-none text-sm"
                    />
                    {r.custom_controls?.trim() && (
                      <p className="mt-1.5 text-[11px] font-medium text-amber-600 dark:text-amber-400">
                        ✓ Бусад хяналт бүртгэгдлээ — 6-р алхамд үр нөлөөг
                        тохируулна уу.
                      </p>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Step 6: Residual Risk ────────────────────────────────────────────────────

const EFFECTIVENESS_OPTIONS = [
  { value: 0, label: "0% — Хэрэгжүүлээгүй" },
  { value: 25, label: "25% — Хэсэгчлэн" },
  { value: 50, label: "50% — Дунд зэрэг" },
  { value: 75, label: "75% — Ихэнх" },
  { value: 100, label: "100% — Бүрэн" },
];

function Step6Residual({
  risks,
  controls,
  onEffectivenessChange,
}: {
  risks: WizardRisk[];
  controls: NistControlOption[];
  onEffectivenessChange: (
    key: string,
    controlId: string,
    effectiveness: number,
  ) => void;
}) {
  const [current, setCurrent] = useState(0);
  const risk = risks[Math.min(current, risks.length - 1)];

  if (!risk) return null;

  const inherentScore = risk.likelihood * risk.impact;
  const inherentLevel = calcLevel(inherentScore);
  const selectedIds = risk.selected_control_ids ?? [];
  const effectivenessMap = risk.control_effectiveness ?? {};
  const { score: residualScore, level: residualLevel } = calcResidualRisk(
    inherentScore,
    selectedIds,
    effectivenessMap,
  );

  const nistSelectedControls = selectedIds
    .filter((id) => id !== "__custom__")
    .map((id) => controls.find((c) => c.control_id === id))
    .filter((c): c is NistControlOption => Boolean(c));

  const hasCustom =
    selectedIds.includes("__custom__") && Boolean(risk.custom_controls?.trim());

  // avgEffectiveness uses ALL selectedIds (includes __custom__ if present)
  const avgEffectiveness =
    selectedIds.length > 0
      ? Math.round(
          selectedIds.reduce(
            (sum, id) => sum + (effectivenessMap[id] ?? 0),
            0,
          ) / selectedIds.length,
        )
      : 0;

  const reduction = inherentScore - residualScore;

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-xl font-bold">
          Хяналтын үр нөлөө ба үлдэгдэл эрсдэл
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Тус бүр хяналтын хэрэгжилтийн түвшинг сонгоно. Систем үлдэгдэл
          эрсдэлийг автоматаар тооцоолно.
        </p>
      </div>

      {/* Risk navigator */}
      <div className="rounded-xl border bg-slate-50 p-3 dark:bg-slate-900/40">
        <div className="mb-3 flex items-center justify-between gap-3">
          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Үнэлэх эрсдэлүүд
          </p>
          <span className="shrink-0 rounded-full bg-white px-2.5 py-1 text-xs font-semibold text-slate-700 shadow-sm dark:bg-slate-950 dark:text-slate-200">
            {current + 1} / {risks.length}
          </span>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {risks.map((r, i) => {
            const iScore = r.likelihood * r.impact;
            const { level: rLevel } = calcResidualRisk(
              iScore,
              r.selected_control_ids ?? [],
              r.control_effectiveness ?? {},
            );
            return (
              <button
                key={r.key}
                type="button"
                onClick={() => setCurrent(i)}
                className={`flex h-8 min-w-8 items-center justify-center rounded-lg border px-2 text-xs font-bold transition-colors ${
                  i === current
                    ? "border-slate-900 bg-slate-900 text-white dark:border-slate-100 dark:bg-slate-100 dark:text-slate-950"
                    : LEVEL_STYLE[rLevel]
                }`}
              >
                {i + 1}
              </button>
            );
          })}
        </div>
      </div>

      {/* Main card */}
      <div className="rounded-xl border bg-white p-5 shadow-sm dark:bg-slate-950">
        <div className="mb-4">
          <p className="text-xs font-semibold text-muted-foreground">
            {risk.asset_name} → {risk.threat_name}
          </p>
          <h3 className="mt-1 text-lg font-bold leading-tight">
            {risk.risk_title}
          </h3>
        </div>

        {/* Inherent → Reduction → Residual visual */}
        <div className="mb-5 grid gap-2 rounded-xl border bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-900/40 md:grid-cols-[1fr_auto_1fr_auto_1fr]">
          <div className="rounded-lg border bg-white px-4 py-3 text-center dark:border-slate-800 dark:bg-slate-950">
            <p className="text-xs font-medium text-muted-foreground">
              Нийт эрсдэл (Inherent)
            </p>
            <p className="text-3xl font-black">{inherentScore}</p>
            <span
              className={`mt-1 inline-block rounded-full border px-2 py-0.5 text-[10px] font-bold ${LEVEL_STYLE[inherentLevel]}`}
            >
              {inherentLevel}
            </span>
          </div>
          <div className="hidden items-center justify-center text-muted-foreground md:flex">
            <ChevronRight className="h-5 w-5" />
          </div>
          <div className="rounded-lg border bg-white px-4 py-3 text-center dark:border-slate-800 dark:bg-slate-950">
            <p className="text-xs font-medium text-muted-foreground">
              Хяналтын бууралт
            </p>
            <p className="text-3xl font-black text-emerald-600">-{reduction}</p>
            <p className="mt-1 text-[10px] text-muted-foreground">
              Дундаж үр нөлөө: {avgEffectiveness}%
            </p>
          </div>
          <div className="hidden items-center justify-center text-muted-foreground md:flex">
            <ChevronRight className="h-5 w-5" />
          </div>
          <div className="rounded-lg border bg-white px-4 py-3 text-center dark:border-slate-800 dark:bg-slate-950">
            <p className="text-xs font-medium text-muted-foreground">
              Үлдэгдэл эрсдэл (Residual)
            </p>
            <p className="text-3xl font-black">{residualScore}</p>
            <span
              className={`mt-1 inline-block rounded-full border px-2 py-0.5 text-[10px] font-bold ${LEVEL_STYLE[residualLevel]}`}
            >
              {residualLevel}
            </span>
          </div>
        </div>

        {/* Formula */}
        <div className="mb-4 rounded-lg border border-blue-100 bg-blue-50 px-3 py-2 text-xs text-blue-700 dark:border-blue-900 dark:bg-blue-950/30 dark:text-blue-300">
          <span className="font-bold">Томьёо: </span>
          Үлдэгдэл = Нийт оноо × (1 − Дундаж үр нөлөө) = {inherentScore} × (1 −{" "}
          {avgEffectiveness / 100}) = {residualScore}
        </div>

        {/* Per-control effectiveness */}
        {nistSelectedControls.length === 0 && !hasCustom ? (
          <div className="rounded-lg border border-dashed py-8 text-center text-sm text-muted-foreground">
            5-р алхамд хяналт сонгоогүй байна. Хяналтгүй тохиолдолд үлдэгдэл
            эрсдэл = нийт эрсдэлтэй тэнцүү.
          </div>
        ) : (
          <div className="space-y-2">
            <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Хяналтуудын хэрэгжилтийн түвшин
            </p>
            {nistSelectedControls.map((control) => {
              const eff = effectivenessMap[control.control_id] ?? 0;
              return (
                <div
                  key={control.control_id}
                  className="flex flex-col gap-2 rounded-lg border p-3 sm:flex-row sm:items-center"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] font-bold text-slate-700 dark:bg-slate-800 dark:text-slate-200">
                        {control.control_id}
                      </span>
                      <span className="text-xs font-medium">
                        {control.control_name ?? "Нэргүй хяналт"}
                      </span>
                    </div>
                    {control.description && (
                      <p className="mt-0.5 line-clamp-1 text-[11px] text-muted-foreground">
                        {control.description}
                      </p>
                    )}
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <select
                      value={eff}
                      onChange={(e) =>
                        onEffectivenessChange(
                          risk.key,
                          control.control_id,
                          Number(e.target.value),
                        )
                      }
                      className="h-8 rounded-md border border-input bg-background px-2 text-xs font-semibold"
                    >
                      {EFFECTIVENESS_OPTIONS.map((opt) => (
                        <option key={opt.value} value={opt.value}>
                          {opt.label}
                        </option>
                      ))}
                    </select>
                    <span
                      className={`w-16 rounded-full border px-2 py-0.5 text-center text-[10px] font-bold ${
                        eff >= 75
                          ? "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-300"
                          : eff >= 50
                            ? "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-300"
                            : eff >= 25
                              ? "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-800 dark:bg-orange-950/30 dark:text-orange-300"
                              : "border-slate-200 bg-slate-50 text-slate-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400"
                      }`}
                    >
                      {eff}%
                    </span>
                  </div>
                </div>
              );
            })}

            {/* Custom / other controls row */}
            {hasCustom && (
              <div className="flex flex-col gap-2 rounded-lg border border-amber-200 bg-amber-50 p-3 dark:border-amber-800 dark:bg-amber-950/20 sm:flex-row sm:items-center">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-bold text-amber-700 dark:bg-amber-950/40 dark:text-amber-300">
                      Бусад
                    </span>
                    <span className="text-xs font-medium">
                      Бусад / Өөрийн хяналт
                    </span>
                  </div>
                  <p className="mt-0.5 line-clamp-2 text-[11px] text-muted-foreground">
                    {risk.custom_controls}
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <select
                    value={effectivenessMap["__custom__"] ?? 50}
                    onChange={(e) =>
                      onEffectivenessChange(
                        risk.key,
                        "__custom__",
                        Number(e.target.value),
                      )
                    }
                    className="h-8 rounded-md border border-input bg-background px-2 text-xs font-semibold"
                  >
                    {EFFECTIVENESS_OPTIONS.map((opt) => (
                      <option key={opt.value} value={opt.value}>
                        {opt.label}
                      </option>
                    ))}
                  </select>
                  <span
                    className={`w-16 rounded-full border px-2 py-0.5 text-center text-[10px] font-bold ${
                      (effectivenessMap["__custom__"] ?? 50) >= 75
                        ? "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-300"
                        : (effectivenessMap["__custom__"] ?? 50) >= 50
                          ? "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-300"
                          : (effectivenessMap["__custom__"] ?? 50) >= 25
                            ? "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-800 dark:bg-orange-950/30 dark:text-orange-300"
                            : "border-slate-200 bg-slate-50 text-slate-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400"
                    }`}
                  >
                    {effectivenessMap["__custom__"] ?? 50}%
                  </span>
                </div>
              </div>
            )}
          </div>
        )}

        <div className="mt-4 flex justify-between">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setCurrent((c) => Math.max(0, c - 1))}
            disabled={current === 0}
          >
            ← Өмнөх
          </Button>
          <Button
            size="sm"
            onClick={() => setCurrent((c) => Math.min(risks.length - 1, c + 1))}
            disabled={current === risks.length - 1}
          >
            Дараах →
          </Button>
        </div>
      </div>
    </div>
  );
}

// ─── Step 4: Likelihood & Impact ─────────────────────────────────────────────

function ScoreSelector({
  label,
  value,
  onChange,
  labels,
  colors,
}: {
  label: string;
  value: number;
  onChange: (v: number) => void;
  labels: Record<number, string>;
  colors: Record<number, string>;
}) {
  return (
    <div>
      <p className="mb-2 text-xs font-semibold text-muted-foreground uppercase tracking-wide">
        {label}
      </p>
      <div className="grid grid-cols-5 gap-1.5">
        {[1, 2, 3, 4, 5].map((v) => (
          <button
            key={v}
            type="button"
            onClick={() => onChange(v)}
            className={`flex min-h-13.5 flex-col items-center justify-center rounded-lg border px-2 py-2 text-center transition-all ${
              value === v
                ? `${colors[v]} ring-2 ring-offset-1`
                : "border-slate-200 bg-white hover:border-slate-300 dark:border-slate-700 dark:bg-slate-900"
            }`}
          >
            <span className="text-lg font-bold leading-none">{v}</span>
            <span
              className={`mt-1 text-[9px] font-medium leading-tight ${value === v ? "" : "text-muted-foreground"}`}
            >
              {labels[v]}
            </span>
          </button>
        ))}
      </div>
    </div>
  );
}

const LIKELIHOOD_COLORS: Record<number, string> = {
  1: "border-emerald-300 bg-emerald-50 text-emerald-800 ring-emerald-200",
  2: "border-lime-300 bg-lime-50 text-lime-800 ring-lime-200",
  3: "border-amber-300 bg-amber-50 text-amber-800 ring-amber-200",
  4: "border-orange-300 bg-orange-50 text-orange-800 ring-orange-200",
  5: "border-red-300 bg-red-50 text-red-800 ring-red-200",
};

const IMPACT_COLORS: Record<number, string> = {
  1: "border-emerald-300 bg-emerald-50 text-emerald-800 ring-emerald-200",
  2: "border-lime-300 bg-lime-50 text-lime-800 ring-lime-200",
  3: "border-amber-300 bg-amber-50 text-amber-800 ring-amber-200",
  4: "border-orange-300 bg-orange-50 text-orange-800 ring-orange-200",
  5: "border-red-300 bg-red-50 text-red-800 ring-red-200",
};

function Step4Score({
  risks,
  onChange,
}: {
  risks: WizardRisk[];
  onChange: (
    key: string,
    field: "likelihood" | "impact",
    value: number,
  ) => void;
}) {
  const [current, setCurrent] = useState(0);
  const risk = risks[current];

  if (!risk) return null;

  const score = risk.likelihood * risk.impact;
  const level = calcLevel(score);
  const matrixRows = [5, 4, 3, 2, 1];
  const matrixColumns = [1, 2, 3, 4, 5];

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-xl font-bold">Магадлал & Нөлөөлөл үнэлгээ</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Тус бүр эрсдэлийн магадлал (1–5) болон нөлөөллийг (1–5) үнэлнэ. Оноо =
          Магадлал × Нөлөөлөл.
        </p>
      </div>

      <div className="rounded-xl border bg-slate-50 p-3 dark:bg-slate-900/40">
        <div className="mb-3 flex items-center justify-between gap-3">
          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Үнэлэх эрсдэлүүд
          </p>
          <span className="shrink-0 rounded-full bg-white px-2.5 py-1 text-xs font-semibold text-slate-700 shadow-sm dark:bg-slate-950 dark:text-slate-200">
            {current + 1} / {risks.length}
          </span>
        </div>
        <div className="mb-3 h-2 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
          <div
            className="h-full bg-emerald-500 transition-all"
            style={{ width: `${((current + 1) / risks.length) * 100}%` }}
          />
        </div>
        <div className="flex flex-wrap gap-1.5">
          {risks.map((r, i) => {
            const s = r.likelihood * r.impact;
            const lv = calcLevel(s);
            return (
              <button
                key={r.key}
                type="button"
                onClick={() => setCurrent(i)}
                className={`flex h-8 min-w-8 items-center justify-center rounded-lg border px-2 text-xs font-bold transition-colors ${
                  i === current
                    ? "border-slate-900 bg-slate-900 text-white dark:border-slate-100 dark:bg-slate-100 dark:text-slate-950"
                    : LEVEL_STYLE[lv]
                }`}
              >
                {i + 1}
              </button>
            );
          })}
        </div>
      </div>

      {/* Score card */}
      <div className="rounded-xl border bg-white p-5 shadow-sm dark:bg-slate-950">
        <div className="mb-4">
          <p className="wrap-break-word text-xs font-semibold text-muted-foreground">
            {risk.asset_name} → {risk.threat_name}
          </p>
          <h3 className="mt-1 text-lg font-bold leading-tight">
            {risk.risk_title}
          </h3>
          {risk.vulnerability_description && (
            <p className="mt-1 text-sm text-muted-foreground line-clamp-2">
              {risk.vulnerability_description}
            </p>
          )}
        </div>

        <div className="grid gap-6 lg:grid-cols-2">
          <ScoreSelector
            label="Магадлал"
            value={risk.likelihood}
            onChange={(v) => onChange(risk.key, "likelihood", v)}
            labels={LIKELIHOOD_LABELS}
            colors={LIKELIHOOD_COLORS}
          />
          <ScoreSelector
            label="Нөлөөлөл"
            value={risk.impact}
            onChange={(v) => onChange(risk.key, "impact", v)}
            labels={IMPACT_LABELS}
            colors={IMPACT_COLORS}
          />
        </div>

        <div className="mt-5 grid gap-3 rounded-xl border bg-slate-50 p-3 dark:border-slate-800 dark:bg-slate-900/40 md:grid-cols-[1fr_auto_1fr_auto_1.2fr_auto] md:items-stretch">
          <div className="rounded-lg border bg-white px-4 py-3 text-center dark:border-slate-800 dark:bg-slate-950">
            <p className="text-xs font-medium text-muted-foreground">
              Магадлал
            </p>
            <p className="text-3xl font-black">{risk.likelihood}</p>
          </div>
          <div className="hidden items-center justify-center text-muted-foreground md:flex">
            <X className="h-5 w-5" />
          </div>
          <div className="rounded-lg border bg-white px-4 py-3 text-center dark:border-slate-800 dark:bg-slate-950">
            <p className="text-xs font-medium text-muted-foreground">
              Нөлөөлөл
            </p>
            <p className="text-3xl font-black">{risk.impact}</p>
          </div>
          <div className="hidden items-center justify-center text-muted-foreground md:flex">
            <ChevronRight className="h-5 w-5" />
          </div>
          <div className="rounded-lg border bg-white px-4 py-3 text-center dark:border-slate-800 dark:bg-slate-950">
            <p className="text-xs font-medium text-muted-foreground">
              Эрсдэлийн оноо
            </p>
            <p className="text-3xl font-black">{score}</p>
          </div>
          <div
            className={`flex min-w-24 flex-col items-center justify-center rounded-lg border px-4 py-3 text-center font-bold ${LEVEL_STYLE[level]}`}
          >
            <p className="text-lg">{levelEmoji(level)}</p>
            <p className="text-xs font-bold">{level}</p>
          </div>
        </div>

        <div className="mt-4 flex justify-between">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setCurrent((c) => Math.max(0, c - 1))}
            disabled={current === 0}
          >
            ← Өмнөх
          </Button>
          <Button
            size="sm"
            onClick={() => setCurrent((c) => Math.min(risks.length - 1, c + 1))}
            disabled={current === risks.length - 1}
          >
            Дараах →
          </Button>
        </div>
      </div>

      {/* Score matrix reference */}
      <div className="rounded-xl border bg-white p-4 dark:bg-slate-950">
        <p className="mb-3 text-xs font-semibold text-muted-foreground uppercase tracking-wide">
          5×5 Эрсдэлийн матриц
        </p>
        <div className="overflow-x-auto">
          <div className="min-w-140">
            <div className="grid grid-cols-[2.5rem_repeat(5,minmax(0,1fr))] gap-1 text-center text-[11px]">
              <div className="flex h-7 items-center justify-center font-semibold text-muted-foreground">
                M \ N
              </div>
              {matrixColumns.map((i) => (
                <div
                  key={i}
                  className="flex h-7 items-center justify-center rounded-md bg-slate-50 font-semibold dark:bg-slate-900"
                >
                  {i}
                </div>
              ))}
              {matrixRows.map((l) => (
                <div key={l} className="contents">
                  <div className="flex h-10 items-center justify-center rounded-md bg-slate-50 font-semibold dark:bg-slate-900">
                    {l}
                  </div>
                  {matrixColumns.map((i) => {
                    const s = l * i;
                    const lv = calcLevel(s);
                    const isCurrent =
                      risk.likelihood === l && risk.impact === i;
                    return (
                      <div
                        key={`${l}-${i}`}
                        className={`flex h-10 items-center justify-center rounded-md border text-xs font-bold transition-all ${LEVEL_STYLE[lv]} ${
                          isCurrent
                            ? "ring-2 ring-inset ring-slate-950 dark:ring-slate-50"
                            : ""
                        }`}
                      >
                        {s}
                      </div>
                    );
                  })}
                </div>
              ))}
            </div>
          </div>
          <div className="mt-3 flex flex-wrap gap-2 text-[10px]">
            {[
              ["Low", "1–4"],
              ["Medium", "5–9"],
              ["High", "10–16"],
              ["Critical", "17–25"],
            ].map(([lv, range]) => (
              <span
                key={lv}
                className={`rounded-full border px-2 py-0.5 font-semibold ${LEVEL_STYLE[lv]}`}
              >
                {lv} ({range})
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Step 5: Review & Save ────────────────────────────────────────────────────

const TREATMENT_OPTIONS: {
  value: string;
  label: string;
  labelMn: string;
  color: string;
  activeColor: string;
}[] = [
  {
    value: "Mitigate",
    label: "Mitigate",
    labelMn: "Бууруулах",
    color:
      "border-blue-200 text-blue-700 hover:bg-blue-50 dark:border-blue-800 dark:text-blue-400 dark:hover:bg-blue-950/40",
    activeColor:
      "border-blue-500 bg-blue-100 text-blue-800 dark:border-blue-500 dark:bg-blue-950/60 dark:text-blue-300",
  },
  {
    value: "Accept",
    label: "Accept",
    labelMn: "Хүлээх",
    color:
      "border-amber-200 text-amber-700 hover:bg-amber-50 dark:border-amber-800 dark:text-amber-400 dark:hover:bg-amber-950/40",
    activeColor:
      "border-amber-500 bg-amber-100 text-amber-800 dark:border-amber-500 dark:bg-amber-950/60 dark:text-amber-300",
  },
  {
    value: "Transfer",
    label: "Transfer",
    labelMn: "Шилжүүлэх",
    color:
      "border-purple-200 text-purple-700 hover:bg-purple-50 dark:border-purple-800 dark:text-purple-400 dark:hover:bg-purple-950/40",
    activeColor:
      "border-purple-500 bg-purple-100 text-purple-800 dark:border-purple-500 dark:bg-purple-950/60 dark:text-purple-300",
  },
  {
    value: "Avoid",
    label: "Avoid",
    labelMn: "Зайлсхийх",
    color:
      "border-rose-200 text-rose-700 hover:bg-rose-50 dark:border-rose-800 dark:text-rose-400 dark:hover:bg-rose-950/40",
    activeColor:
      "border-rose-500 bg-rose-100 text-rose-800 dark:border-rose-500 dark:bg-rose-950/60 dark:text-rose-300",
  },
];

function Step5Review({
  risks,
  saving,
  saved,
  onSave,
  onTreatmentChange,
}: {
  risks: WizardRisk[];
  saving: boolean;
  saved: boolean;
  onSave: () => void;
  onTreatmentChange: (key: string, treatment: string | null) => void;
}) {
  const byLevel = risks.reduce(
    (acc, r) => {
      const lv = calcLevel(r.likelihood * r.impact);
      acc[lv] = (acc[lv] ?? 0) + 1;
      return acc;
    },
    {} as Record<string, number>,
  );

  const sorted = [...risks].sort(
    (a, b) => b.likelihood * b.impact - a.likelihood * a.impact,
  );

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold">Хянах & Хадгалах</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Бүх эрсдэлийг хянаад баталгаажуулна уу. &ldquo;Хадгалах&rdquo; дарахад
          систем эрсдэлийн бүртгэлд нэмнэ.
        </p>
      </div>

      {/* Summary tiles */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {(["Critical", "High", "Medium", "Low"] as const).map((lv) => (
          <div
            key={lv}
            className={`rounded-xl border p-3 text-center ${LEVEL_STYLE[lv]}`}
          >
            <p className="text-2xl font-black">{byLevel[lv] ?? 0}</p>
            <p className="text-xs font-semibold">{lv}</p>
          </div>
        ))}
      </div>

      {/* Risk list */}
      <div className="space-y-2">
        {sorted.map((r, i) => {
          const score = r.likelihood * r.impact;
          const level = calcLevel(score);
          return (
            <div
              key={r.key}
              className={`rounded-lg border p-3 ${r.saved ? "opacity-60" : ""}`}
            >
              <div className="flex items-start gap-3">
                <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-slate-100 text-xs font-bold dark:bg-slate-800">
                  {i + 1}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-semibold">
                      {r.risk_title}
                    </span>
                    <span
                      className={`rounded-full border px-2 py-0.5 text-[10px] font-bold ${LEVEL_STYLE[level]}`}
                    >
                      {levelEmoji(level)} {level}
                    </span>
                    {r.saved && (
                      <span className="text-[10px] font-semibold text-emerald-600">
                        ✓ Хадгалагдсан
                      </span>
                    )}
                  </div>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    {r.asset_name} → {r.threat_name}
                  </p>
                  <div className="mt-1.5 flex flex-wrap gap-3 text-xs text-muted-foreground">
                    <span>
                      Магадлал: <strong>{r.likelihood}</strong> (
                      {LIKELIHOOD_LABELS[r.likelihood]})
                    </span>
                    <span>
                      Нөлөөлөл: <strong>{r.impact}</strong> (
                      {IMPACT_LABELS[r.impact]})
                    </span>
                    <span>
                      Нийт оноо: <strong>{score}</strong>
                    </span>
                    {r.residual_risk_score != null &&
                      r.residual_risk_score !== score && (
                        <span className="font-semibold text-emerald-600 dark:text-emerald-400">
                          → Үлдэгдэл: <strong>{r.residual_risk_score}</strong>
                          <span
                            className={`ml-1 rounded-full border px-1.5 py-0.5 text-[9px] font-bold ${LEVEL_STYLE[r.residual_risk_level ?? "Low"]}`}
                          >
                            {r.residual_risk_level}
                          </span>
                        </span>
                      )}
                  </div>
                  {r.vulnerability_description && (
                    <p className="mt-1 text-xs text-muted-foreground line-clamp-1">
                      <span className="font-medium">Эмзэг байдал:</span>{" "}
                      {r.vulnerability_description}
                    </p>
                  )}

                  {/* Risk treatment selector */}
                  {!r.saved && (
                    <div className="mt-2.5">
                      <p className="mb-1.5 text-[11px] font-semibold text-muted-foreground uppercase tracking-wide">
                        Эрсдэлийн хариу арга хэмжээ
                      </p>
                      <div className="flex flex-wrap gap-1.5">
                        {TREATMENT_OPTIONS.map((opt) => {
                          const isActive = r.treatment === opt.value;
                          return (
                            <button
                              key={opt.value}
                              type="button"
                              onClick={() =>
                                onTreatmentChange(
                                  r.key,
                                  isActive ? null : opt.value,
                                )
                              }
                              className={`rounded-full border px-2.5 py-0.5 text-[11px] font-semibold transition-colors ${
                                isActive ? opt.activeColor : opt.color
                              }`}
                            >
                              {isActive ? "✓ " : ""}
                              {opt.labelMn} / {opt.label}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  )}
                  {r.saved && r.treatment && (
                    <p className="mt-1.5 text-[11px] font-semibold text-emerald-600 dark:text-emerald-400">
                      Арга:{" "}
                      {TREATMENT_OPTIONS.find((o) => o.value === r.treatment)
                        ?.labelMn ?? r.treatment}
                    </p>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {!saved && risks.length > 0 && (
        <div className="flex justify-end">
          <Button
            onClick={onSave}
            disabled={saving}
            className="bg-emerald-600 hover:bg-emerald-700 text-white"
            size="lg"
          >
            {saving ? (
              <>
                <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                Хадгалж байна…
              </>
            ) : (
              <>
                <Save className="mr-2 h-4 w-4" />
                {risks.length} эрсдэл хадгалах
              </>
            )}
          </Button>
        </div>
      )}

      {saved && (
        <div className="flex items-center gap-3 rounded-xl border border-emerald-200 bg-emerald-50 p-4 dark:border-emerald-800 dark:bg-emerald-950/30">
          <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-600" />
          <div>
            <p className="text-sm font-semibold text-emerald-800 dark:text-emerald-300">
              Амжилттай хадгалагдлаа!
            </p>
            <p className="text-xs text-emerald-700 dark:text-emerald-400">
              {risks.length} эрсдэл эрсдэлийн бүртгэлд нэмэгдлээ.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function RiskAssessmentPage() {
  const { user } = useAuth();
  const [step, setStep] = useState(1);
  const [subjectType, setSubjectType] = useState<SubjectType>("asset");
  const [method, setMethod] = useState<Method>("asset_threat");

  // Data
  const [assetMappings, setAssetMappings] = useState<AssetThreatMapping[]>([]);
  const [allAssets, setAllAssets] = useState<AssetOption[]>([]);
  const [allThreats, setAllThreats] = useState<ThreatOption[]>([]);
  const [savedRisks, setSavedRisks] = useState<SavedRisk[]>([]);
  const [nistControls, setNistControls] = useState<NistControlOption[]>([]);
  const [scopeDepartments, setScopeDepartments] = useState<ScopeDepartment[]>(
    [],
  );
  const [loadingData, setLoadingData] = useState(false);

  // Wizard state
  const [selectedPairKeys, setSelectedPairKeys] = useState<Set<string>>(
    new Set(),
  );
  const [wizardRisks, setWizardRisks] = useState<WizardRisk[]>([]);
  const [frameworkKeys, setFrameworkKeys] = useState<Set<string>>(new Set());

  // Save state
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [message, setMessage] = useState<{
    tone: "success" | "error";
    text: string;
  } | null>(null);

  // Auto-route the methodology based on object type:
  //   asset → asset-threat pairing (NIST SP 800-30)
  //   everything else → NIST CSF 2.0 framework subcategories (ID.RA-3)
  function handleSubjectChange(next: SubjectType) {
    setSubjectType(next);
    setMethod(next === "asset" ? "asset_threat" : "framework");
    setSelectedPairKeys(new Set());
    setFrameworkKeys(new Set());
    setWizardRisks([]);
  }

  const fetchData = useCallback(async () => {
    setLoadingData(true);
    try {
      const [
        mappingsRes,
        assetsRes,
        threatsRes,
        risksRes,
        vulnsRes,
        scopeRes,
        controlsRes,
      ] = await Promise.all([
        fetch("/api/threats/by-asset"),
        fetch("/api/assets"),
        fetch("/api/threats"),
        fetch("/api/risk-register"),
        fetch("/api/vulnerabilities"),
        fetch("/api/csf-scope"),
        fetch("/api/controls"),
      ]);
      const savedRiskRows = risksRes.ok
        ? ((await risksRes.json()).risks ?? [])
        : [];
      if (risksRes.ok) setSavedRisks(savedRiskRows);
      if (mappingsRes.ok) {
        const data = await mappingsRes.json();
        let mappings = (data.assets ?? []) as AssetThreatMapping[];
        if (vulnsRes.ok) {
          const vulnData = await vulnsRes.json();
          mappings = filterMappingsToVisibleThreats(
            mappings,
            vulnData.vulnerabilities ?? [],
            savedRiskRows,
          );
        }
        setAssetMappings(mappings);
      }
      if (assetsRes.ok) {
        const data = await assetsRes.json();
        setAllAssets(data.assets ?? []);
      }
      if (threatsRes.ok) {
        const data = await threatsRes.json();
        const threats = Array.isArray(data) ? data : (data.threats ?? []);
        setAllThreats(threats);
      }
      if (scopeRes.ok) {
        const data = (await scopeRes.json()) as ScopePayload;
        const departments = data.departments ?? [];
        const selectedIds = new Set(
          (data.assessment_scope?.selected_department_ids ?? []).map(Number),
        );
        setScopeDepartments(
          selectedIds.size > 0
            ? departments.filter((dept) => selectedIds.has(Number(dept.id)))
            : departments,
        );
      }
      if (controlsRes.ok) {
        const data = await controlsRes.json();
        setNistControls((data.controls ?? []) as NistControlOption[]);
      }
    } finally {
      setLoadingData(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const controlsById = useMemo(
    () =>
      new Map(
        nistControls.map((control) => [control.control_id, control] as const),
      ),
    [nistControls],
  );

  // Build wizard risks when step 2 selections change
  function buildRisksFromPairs() {
    const risks: WizardRisk[] = [];
    for (const key of selectedPairKeys) {
      const [assetIdStr, threatIdStr] = key.split("-");
      const assetId = Number(assetIdStr);
      const threatId = Number(threatIdStr);
      const asset = assetMappings.find((a) => a.asset_id === assetId);
      const threat = asset?.threats.find((t) => t.id === threatId);
      if (!asset || !threat) continue;
      risks.push({
        key,
        asset_id: assetId,
        asset_name: asset.asset_name,
        asset_type: asset.asset_type,
        asset_criticality: asset.criticality,
        threat_id: threatId,
        threat_name: threat.threat_name,
        threat_type: threat.threat_type,
        nist_category: threat.nist_category,
        risk_title: `${threat.threat_name} — ${asset.asset_name}`,
        vulnerability_description: threat.description ?? "",
        key_controls: threat.mitigation_notes ?? "",
        selected_control_ids: [],
        risk_owner: "",
        dept_owner: "",
        nist_csf_function: "",
        nist_csf_category: threat.nist_category ?? "",
        likelihood: Math.max(1, Math.min(5, threat.likelihood_level ?? 3)),
        impact: asset.criticality?.toLowerCase().includes("tier 0")
          ? 5
          : asset.criticality?.toLowerCase().includes("tier 1")
            ? 4
            : asset.criticality?.toLowerCase().includes("tier 2")
              ? 3
              : 3,
        treatment: null,
        saved: false,
        control_effectiveness: {},
        residual_risk_score: null,
        residual_risk_level: null,
        custom_controls: "",
      });
    }
    return risks;
  }

  function buildRisksFromFramework() {
    const risks: WizardRisk[] = [];
    for (const key of frameworkKeys) {
      const template = FRAMEWORK_RISKS.find(
        (t) => `fw-${t.category_code}-${t.risk_title.slice(0, 20)}` === key,
      );
      if (!template) continue;
      risks.push({
        key,
        asset_id: 0,
        asset_name: "Байгууллагын ерөнхий",
        asset_type: null,
        asset_criticality: null,
        threat_id: 0,
        threat_name: template.category_name,
        threat_type: "Framework",
        nist_category: template.category_code,
        risk_title: template.risk_title,
        vulnerability_description: template.vulnerability_description,
        key_controls: "",
        selected_control_ids: [],
        risk_owner: "",
        dept_owner: "",
        nist_csf_function: template.function_code,
        nist_csf_category: template.category_code,
        likelihood: 3,
        impact: 3,
        treatment: null,
        saved: false,
        control_effectiveness: {},
        residual_risk_score: null,
        residual_risk_level: null,
        custom_controls: "",
      });
    }
    return risks;
  }

  function handleTogglePair(key: string) {
    setSelectedPairKeys((prev) => {
      const s = new Set(prev);
      if (s.has(key)) {
        s.delete(key);
      } else {
        s.add(key);
      }
      return s;
    });
  }

  function handleToggleFramework(key: string) {
    setFrameworkKeys((prev) => {
      const s = new Set(prev);
      if (s.has(key)) {
        s.delete(key);
      } else {
        s.add(key);
      }
      return s;
    });
  }

  function handleVulnChange(
    key: string,
    field: keyof WizardRisk,
    value: string,
  ) {
    setWizardRisks((prev) =>
      prev.map((r) => (r.key === key ? { ...r, [field]: value } : r)),
    );
  }

  function handleToggleWizardControl(key: string, controlId: string) {
    setWizardRisks((prev) =>
      prev.map((risk) => {
        if (risk.key !== key) return risk;
        const selectedIds = risk.selected_control_ids ?? [];
        const isAdding = !selectedIds.includes(controlId);
        const nextIds = isAdding
          ? [...selectedIds, controlId]
          : selectedIds.filter((id) => id !== controlId);
        const newEffectiveness = { ...(risk.control_effectiveness ?? {}) };
        if (isAdding) {
          newEffectiveness[controlId] = 50; // default 50%
        } else {
          delete newEffectiveness[controlId];
        }
        const inherentScore = risk.likelihood * risk.impact;
        const { score: residualScore, level: residualLevel } = calcResidualRisk(
          inherentScore,
          nextIds,
          newEffectiveness,
        );
        return {
          ...risk,
          selected_control_ids: nextIds,
          control_effectiveness: newEffectiveness,
          residual_risk_score: residualScore,
          residual_risk_level: residualLevel,
        };
      }),
    );
  }

  function handleControlEffectivenessChange(
    key: string,
    controlId: string,
    effectiveness: number,
  ) {
    setWizardRisks((prev) =>
      prev.map((risk) => {
        if (risk.key !== key) return risk;
        const newEffectiveness = {
          ...(risk.control_effectiveness ?? {}),
          [controlId]: effectiveness,
        };
        const inherentScore = risk.likelihood * risk.impact;
        const { score: residualScore, level: residualLevel } = calcResidualRisk(
          inherentScore,
          risk.selected_control_ids ?? [],
          newEffectiveness,
        );
        return {
          ...risk,
          control_effectiveness: newEffectiveness,
          residual_risk_score: residualScore,
          residual_risk_level: residualLevel,
        };
      }),
    );
  }

  function handleCustomControlsChange(key: string, value: string) {
    setWizardRisks((prev) =>
      prev.map((risk) => {
        if (risk.key !== key) return risk;
        const hasText = value.trim().length > 0;
        const currentIds = risk.selected_control_ids ?? [];
        const hasCustomId = currentIds.includes("__custom__");

        let nextIds = currentIds;
        const newEffectiveness = { ...(risk.control_effectiveness ?? {}) };

        if (hasText && !hasCustomId) {
          nextIds = [...currentIds, "__custom__"];
          newEffectiveness["__custom__"] = 50; // default 50%
        } else if (!hasText && hasCustomId) {
          nextIds = currentIds.filter((id) => id !== "__custom__");
          delete newEffectiveness["__custom__"];
        }

        const inherentScore = risk.likelihood * risk.impact;
        const { score: residualScore, level: residualLevel } = calcResidualRisk(
          inherentScore,
          nextIds,
          newEffectiveness,
        );

        return {
          ...risk,
          custom_controls: value,
          selected_control_ids: nextIds,
          control_effectiveness: newEffectiveness,
          residual_risk_score: residualScore,
          residual_risk_level: residualLevel,
        };
      }),
    );
  }

  function handleScoreChange(
    key: string,
    field: "likelihood" | "impact",
    value: number,
  ) {
    setWizardRisks((prev) =>
      prev.map((r) => {
        if (r.key !== key) return r;
        const updated = { ...r, [field]: value };
        const inherentScore = updated.likelihood * updated.impact;
        const { score: residualScore, level: residualLevel } = calcResidualRisk(
          inherentScore,
          updated.selected_control_ids ?? [],
          updated.control_effectiveness ?? {},
        );
        return {
          ...updated,
          residual_risk_score: residualScore,
          residual_risk_level: residualLevel,
        };
      }),
    );
  }

  function handleTreatmentChange(key: string, treatment: string | null) {
    setWizardRisks((prev) =>
      prev.map((r) => (r.key === key ? { ...r, treatment } : r)),
    );
  }

  function getCurrentRisks(): WizardRisk[] {
    if (method === "asset_threat") return buildRisksFromPairs();
    if (method === "framework") return buildRisksFromFramework();
    return wizardRisks;
  }

  function prepareStep3Or4() {
    const current = getCurrentRisks();
    // Merge with existing wizard risks to preserve edits
    const existingByKey = new Map(wizardRisks.map((r) => [r.key, r]));
    const merged = current.map((risk) => {
      const existing = existingByKey.get(risk.key);
      return existing
        ? {
            ...risk,
            ...existing,
            selected_control_ids: existing.selected_control_ids ?? [],
          }
        : risk;
    });
    setWizardRisks(merged);
  }

  async function handleNext() {
    setMessage(null);
    if (step === 1 && !method) {
      setMessage({ tone: "error", text: "Хөрөнгө сонгоно уу" });
      return;
    }
    if (step === 2) {
      const count =
        method === "asset_threat"
          ? selectedPairKeys.size
          : method === "framework"
            ? frameworkKeys.size
            : wizardRisks.length;
      if (count === 0) {
        setMessage({ tone: "error", text: "Дор хаяж нэг эрсдэл сонгоно уу" });
        return;
      }
      prepareStep3Or4();
    }
    setStep((s) => Math.min(7, s + 1));
  }

  async function handleSave() {
    setSaving(true);
    setMessage(null);
    let successCount = 0;
    let errorCount = 0;
    let controlErrorCount = 0;

    // Build a set of already-saved framework risk titles to avoid re-saving
    const savedFrameworkTitles = new Set(
      savedRisks
        .filter((s) => !s.asset_id && !s.threat_id)
        .map((s) => `${s.risk_title}__${s.nist_csf_category ?? ""}`),
    );

    for (const risk of wizardRisks) {
      if (risk.saved) continue;
      // Skip framework risks that are already in the database
      if (
        risk.threat_type === "Framework" &&
        savedFrameworkTitles.has(
          `${risk.risk_title}__${risk.nist_csf_category ?? ""}`,
        )
      ) {
        continue;
      }
      try {
        const selectedControls = (risk.selected_control_ids ?? [])
          .map((id) => controlsById.get(id))
          .filter((control): control is NistControlOption => Boolean(control));
        const selectedControlText = selectedControls
          .map(
            (control) =>
              `${control.control_id} - ${control.control_name ?? "Нэргүй хяналт"}`,
          )
          .join("\n");
        const noteText = risk.key_controls.trim();
        const customText = risk.custom_controls?.trim() ?? "";
        const keyControlsText = [
          selectedControlText,
          noteText ? `Нэмэлт тайлбар:\n${noteText}` : "",
          customText ? `Бусад хяналт:\n${customText}` : "",
        ]
          .filter(Boolean)
          .join("\n\n");

        // Create risk register entry
        const rrRes = await fetch("/api/risk-register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            asset_id: risk.asset_id || null,
            threat_id: risk.threat_id || null,
            risk_title: risk.risk_title,
            risk_description: risk.vulnerability_description,
            vulnerability_description: risk.vulnerability_description,
            key_controls: keyControlsText,
            risk_owner: risk.risk_owner || null,
            department_control_owner: risk.dept_owner || null,
            nist_csf_function: risk.nist_csf_function || null,
            nist_csf_category: risk.nist_csf_category || null,
            assessed_by: user?.name ?? user?.email ?? null,
          }),
        });

        if (!rrRes.ok) {
          const errText = await rrRes.text().catch(() => rrRes.statusText);
          console.error("Risk register POST failed:", rrRes.status, errText);
          errorCount++;
          continue;
        }
        const rrData = await rrRes.json();
        const dbId: number = rrData.risk?.id ?? rrData.id;

        if (dbId) {
          // Create risk analysis
          await fetch("/api/risk-analysis", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              risk_id: dbId,
              likelihood: risk.likelihood,
              impact: risk.impact,
              residual_risk_score: risk.residual_risk_score ?? null,
              residual_risk_level: risk.residual_risk_level ?? null,
              business_impact_description: risk.vulnerability_description,
              assessed_by: user?.name ?? user?.email ?? null,
            }),
          });

          // Save selected risk treatment if one was chosen
          if (risk.treatment) {
            await fetch("/api/risk-register", {
              method: "PATCH",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                risk_register_id: dbId,
                risk_treatment: risk.treatment,
              }),
            });
          }

          if (selectedControls.length > 0) {
            try {
              const linkResponses = await Promise.all(
                selectedControls.map((control) =>
                  fetch("/api/controls/select", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                      risk_register_id: dbId,
                      control_id: control.control_id,
                      control_name: control.control_name,
                      nist_function: control.nist_csf_function,
                      domain: control.domain,
                      priority:
                        control.priority != null
                          ? String(control.priority)
                          : null,
                    }),
                  }),
                ),
              );
              const failedLinks = linkResponses.filter((res) => !res.ok);
              if (failedLinks.length > 0) {
                controlErrorCount += failedLinks.length;
                console.error(
                  "Control link failed:",
                  failedLinks.map((res) => res.status).join(", "),
                );
              }
            } catch (error) {
              controlErrorCount += selectedControls.length;
              console.error("Control link failed:", error);
            }
          }

          setWizardRisks((prev) =>
            prev.map((r) =>
              r.key === risk.key ? { ...r, saved: true, db_id: dbId } : r,
            ),
          );
          successCount++;
        }
      } catch {
        errorCount++;
      }
    }

    setSaving(false);
    if (errorCount === 0) {
      const savedPairKeys = new Set(
        wizardRisks
          .filter((risk) => risk.asset_id && risk.threat_id)
          .map((risk) => `${risk.asset_id}-${risk.threat_id}`),
      );
      setSelectedPairKeys((prev) => {
        const next = new Set(prev);
        savedPairKeys.forEach((key) => next.delete(key));
        return next;
      });
      setSaved(true);
      setMessage({
        tone: controlErrorCount > 0 ? "error" : "success",
        text:
          controlErrorCount > 0
            ? `${successCount} эрсдэл хадгалагдлаа, ${controlErrorCount} хяналт холбогдсонгүй.`
            : `${successCount} эрсдэл амжилттай хадгалагдлаа!`,
      });
      await fetchData();
    } else {
      setMessage({
        tone: "error",
        text: `${successCount} амжилттай, ${errorCount} алдаатай.`,
      });
    }
  }

  const currentRisks = step >= 3 ? wizardRisks : getCurrentRisks();

  return (
    <div className="app-page p-4 pb-8 sm:p-6 md:p-8">
      <div className="mx-auto max-w-5xl space-y-6">
        {/* Header */}
        <div className="mb-6">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-3xl font-bold sm:text-4xl">
              Эрсдэлийн үнэлгээ
            </h1>
          </div>
        </div>

        {/* Step indicator */}
        <div className="rounded-xl border bg-white p-3 shadow-sm dark:bg-slate-950">
          <StepIndicator
            current={step}
            onNavigate={(n) => {
              if (n < step) setStep(n);
            }}
          />
        </div>

        {/* Message */}
        {message && (
          <div
            className={`flex items-center gap-2 rounded-lg border px-4 py-3 text-sm ${
              message.tone === "success"
                ? "border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-300"
                : "border-rose-200 bg-rose-50 text-rose-800 dark:border-rose-800 dark:bg-rose-950/30 dark:text-rose-300"
            }`}
          >
            {message.tone === "success" ? (
              <CheckCircle2 className="h-4 w-4 shrink-0" />
            ) : (
              <AlertTriangle className="h-4 w-4 shrink-0" />
            )}
            {message.text}
          </div>
        )}

        {/* Step content */}
        <div className="rounded-xl border bg-white p-6 shadow-sm dark:bg-slate-950">
          {step === 1 && (
            <Step1Method
              subjectType={subjectType}
              onSubjectChange={handleSubjectChange}
            />
          )}

          {step === 2 && method === "asset_threat" && (
            <Step2AssetThreat
              mappings={assetMappings}
              selected={selectedPairKeys}
              onToggle={handleTogglePair}
              loading={loadingData}
            />
          )}
          {step === 2 && method === "framework" && (
            <Step2Framework
              subjectType={subjectType}
              selectedKeys={frameworkKeys}
              onToggle={handleToggleFramework}
              savedRisks={savedRisks}
            />
          )}

          {step === 3 && (
            <Step3Vuln risks={currentRisks} onChange={handleVulnChange} />
          )}

          {step === 4 && (
            <Step4Score risks={currentRisks} onChange={handleScoreChange} />
          )}

          {step === 5 && (
            <Step5Controls
              risks={currentRisks}
              controls={nistControls}
              onToggleControl={handleToggleWizardControl}
              onCustomControlsChange={handleCustomControlsChange}
            />
          )}

          {step === 6 && (
            <Step6Residual
              risks={currentRisks}
              controls={nistControls}
              onEffectivenessChange={handleControlEffectivenessChange}
            />
          )}

          {step === 7 && (
            <Step5Review
              risks={currentRisks}
              saving={saving}
              saved={saved}
              onSave={handleSave}
              onTreatmentChange={handleTreatmentChange}
            />
          )}
        </div>

        {/* Navigation */}
        <div className="flex items-center justify-between">
          <Button
            variant="outline"
            onClick={() => {
              setMessage(null);
              setStep((s) => Math.max(1, s - 1));
            }}
            disabled={step === 1}
          >
            ← Өмнөх
          </Button>
          <span className="text-xs text-muted-foreground">
            {step} / {STEPS.length}
          </span>
          {step < 7 ? (
            <Button onClick={handleNext}>Дараах →</Button>
          ) : (
            <Button
              variant="outline"
              onClick={() => {
                setStep(1);
                setSubjectType("asset");
                setMethod("asset_threat");
                setWizardRisks([]);
                setSelectedPairKeys(new Set());
                setFrameworkKeys(new Set());
                setSaved(false);
                setMessage(null);
              }}
            >
              <RefreshCw className="mr-2 h-4 w-4" />
              Шинэ үнэлгээ
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
