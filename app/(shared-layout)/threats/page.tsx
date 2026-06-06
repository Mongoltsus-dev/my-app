"use client";

import {
  AlertTriangle,
  Bug,
  ChevronLeft,
  ChevronRight,
  Database,
  Filter,
  RotateCcw,
  Search,
  ShieldAlert,
  X,
} from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";

interface LinkedAssetType {
  type_name: string;
  risk_level: string;
}

interface LinkedAsset {
  id: number;
  asset_name: string;
  asset_code: string | null;
  asset_type: string | null;
  criticality: string | null;
  internet_exposed: boolean;
  status: string | null;
  risk_level: string;
  matched_asset_type: string;
}

interface Threat {
  id: number;
  threat_name: string;
  description: string | null;
  description_mn: string | null;
  threat_type: string | null;
  likelihood_level: number | null;
  potential_impact: string | null;
  nist_category: string | null;
  mitigation_notes: string | null;
  mitigation_notes_mn: string | null;
  risk_level: string;
  linked_assets: LinkedAsset[];
  linked_asset_types: LinkedAssetType[];
  registered_asset_count: number;
}

interface ThreatTableRow {
  key: string;
  threat_id: number;
  threat_name: string;
  threat_type: string | null;
  description: string | null;
  mitigation: string | null;
  risk_level: "Critical" | "High" | "Medium" | "Low";
  asset: LinkedAsset;
  vulnerabilities: Vulnerability[];
  openCount: number;
  criticalCount: number;
}

type VulnStatus = "open" | "in_progress" | "remediated" | "accepted";

interface Vulnerability {
  id: number;
  asset_id: number | null;
  threat_id: number | null;
  cve_id: string | null;
  title: string;
  description: string | null;
  vulnerability_type: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  cvss_score: string | null;
  status: VulnStatus;
  discovered_at: string;
  remediated_at: string | null;
  remediation_notes: string | null;
  reference_url: string | null;
  source: string;
  asset_name: string | null;
  threat_name: string | null;
  threat_type: string | null;
  threat_description: string | null;
  threat_likelihood_level: number | null;
  threat_potential_impact: string | null;
  threat_nist_category: string | null;
  threat_mapping_risk_level: string | null;
  threat_mitigation_notes: string | null;
  threat_mitigation_notes_mn: string | null;
}

const ALL = "Бүгд";

const RISK_COLORS: Record<string, string> = {
  Critical:
    "border-red-200 bg-red-50 text-red-700 dark:border-red-900/70 dark:bg-red-950/40 dark:text-red-300",
  High: "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-900/70 dark:bg-orange-950/40 dark:text-orange-300",
  Medium:
    "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900/70 dark:bg-amber-950/40 dark:text-amber-300",
  Low: "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900/70 dark:bg-emerald-950/40 dark:text-emerald-300",
  Unknown:
    "border-slate-200 bg-slate-50 text-slate-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300",
};

const RISK_ACCENTS: Record<string, string> = {
  Critical: "bg-red-500",
  High: "bg-orange-500",
  Medium: "bg-amber-500",
  Low: "bg-emerald-500",
  Unknown: "bg-slate-400",
};

const RISK_LABELS: Record<string, string> = {
  Critical: "Ноцтой",
  High: "Өндөр",
  Medium: "Дунд",
  Low: "Бага",
  Unknown: "Тодорхойгүй",
};

const ASSET_TYPE_LABELS: Record<string, string> = {
  Identity: "Нэвтрэлтийн систем",
  "Identity Provider": "Нэвтрэлтийн систем",
  Database: "Мэдээллийн сан",
  Application: "Аппликейшн",
  Service: "Үйлчилгээ",
  Server: "Сервер",
  "Web Server": "Вэб сервер",
  Network: "Сүлжээ",
  "SaaS Tenant": "SaaS орчин",
  Cloud: "Үүлэн орчин",
  Data: "Өгөгдөл",
  Hardware: "Техник хангамж",
  Software: "Програм хангамж",
};

const THREAT_TYPE_LABELS: Record<string, string> = {
  Adversarial: "Халдагчийн үйлдэл",
  Attack: "Халдлага",
  Human: "Хүний хүчин зүйл",
  Application: "Аппликейшн",
  Malware: "Хортой код",
  Availability: "Хүртээмж",
  Network: "Сүлжээ",
  "Third-Party": "Гуравдагч тал",
  Vulnerability: "Эмзэг байдал",
  Configuration: "Тохиргоо",
  Data: "Өгөгдөл",
  Cryptography: "Криптограф",
  "Access Control": "Хандалтын хяналт",
  Monitoring: "Хяналт, лог",
  Cloud: "Үүлэн орчин",
  Technical: "Техникийн",
};

const THREAT_NAME_LABELS: Record<string, string> = {
  "Account Takeover": "хэрэглэгчийн бүртгэл эзлэгдэх",
  "Brute Force / Credential Stuffing": "нууц үг таах халдлага",
  "Credential Reuse / Password Spraying": "нууц үг дахин ашиглах халдлага",
  "Credential Theft": "нэвтрэх мэдээлэл алдагдах",
  "Data Exfiltration": "өгөгдөл гадагш алдагдах",
  Malware: "хортой кодын халдлага",
  "Phishing / Spear Phishing": "фишинг халдлага",
  Ransomware: "ransomware халдлага",
  "Unauthorized Access": "зөвшөөрөлгүй хандалт",
  "Unauthorised Access": "зөвшөөрөлгүй хандалт",
};

const STATUS_LABELS: Record<string, string> = {
  Active: "Идэвхтэй",
  Inactive: "Идэвхгүй",
  Deprecated: "Ашиглалтаас гарсан",
  Planned: "Төлөвлөсөн",
};

const CRITICALITY_LABELS: Record<string, string> = {
  "Tier 0 (Life/Safety)": "Түвшин 0 (Амь нас/аюулгүй байдал)",
  "Tier 1 (Mission Critical)": "Түвшин 1 (Үйл ажиллагаанд нэн чухал)",
  "Tier 2 (Business Critical)": "Түвшин 2 (Бизнесийн чухал)",
  "Tier 3 (Operational)": "Түвшин 3 (Үйл ажиллагааны)",
};

// ── Vulnerability constants ──────────────────────────────────────
const VULN_SEVERITY_STYLES: Record<string, string> = {
  Critical:
    "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20",
  High: "bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20",
  Medium:
    "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20",
  Low: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20",
};

const VULN_STATUS_STYLES: Record<string, string> = {
  open: "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20",
  in_progress:
    "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20",
  remediated:
    "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20",
  accepted:
    "bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-500/20",
};

const VULN_STATUS_LABEL: Record<string, string> = {
  open: "Нээлттэй",
  in_progress: "Хийгдэж буй",
  remediated: "Засварласан",
  accepted: "Хүлээн зөвшөөрсөн",
};

const VULN_SEVERITY_LABEL: Record<string, string> = {
  Critical: "Ноцтой",
  High: "Өндөр",
  Medium: "Дунд",
  Low: "Бага",
};

const labelOrOriginal = (
  labels: Record<string, string>,
  value: string | null | undefined,
) => {
  if (!value) return "—";
  return labels[value] ?? value;
};

const riskLabel = (value: string | null | undefined) =>
  labelOrOriginal(RISK_LABELS, value || "Unknown");

const assetTypeLabel = (value: string | null | undefined) =>
  labelOrOriginal(ASSET_TYPE_LABELS, value);

const threatTypeLabel = (value: string | null | undefined) =>
  labelOrOriginal(THREAT_TYPE_LABELS, value);

const statusLabel = (value: string | null | undefined) =>
  labelOrOriginal(STATUS_LABELS, value);

const criticalityLabel = (value: string | null | undefined) =>
  labelOrOriginal(CRITICALITY_LABELS, value);

const getRiskColor = (riskLevel: string | null | undefined) =>
  RISK_COLORS[riskLevel || "Unknown"] ?? RISK_COLORS.Unknown;

const getRiskAccent = (riskLevel: string | null | undefined) =>
  RISK_ACCENTS[riskLevel || "Unknown"] ?? RISK_ACCENTS.Unknown;

const riskWeight = (riskLevel: string | null | undefined) => {
  switch (riskLevel) {
    case "Critical":
      return 4;
    case "High":
      return 3;
    case "Medium":
      return 2;
    case "Low":
      return 1;
    default:
      return 0;
  }
};

const severityWeight = (severity: string | null | undefined) =>
  riskWeight(severity);

const getCriticalityColor = (criticality: string | null) => {
  if (criticality?.includes("Tier 0"))
    return "bg-red-100 text-red-700 dark:bg-red-950/50 dark:text-red-300";
  if (criticality?.includes("Tier 1"))
    return "bg-orange-100 text-orange-700 dark:bg-orange-950/50 dark:text-orange-300";
  if (criticality?.includes("Tier 2"))
    return "bg-yellow-100 text-yellow-700 dark:bg-yellow-950/50 dark:text-yellow-300";
  return "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-300";
};

const translateThreatPhrase = (value: string) =>
  THREAT_NAME_LABELS[value.trim()] ?? value;

const translateMitigationText = (value: string | null | undefined) => {
  if (!value) return value ?? null;

  return value
    .replace(
      /Enforce MFA; review OAuth app permissions; monitor sign-in logs\./g,
      "MFA-г албажуулж, OAuth аппын зөвшөөрлүүдийг хянаж, нэвтрэлтийн логийг тогтмол шалгана.",
    )
    .replace(
      /Enforce MFA; monitor login anomalies; review OAuth integrations\./g,
      "MFA-г албажуулж, хэвийн бус нэвтрэлтийг хянаж, OAuth холболтуудыг шалгана.",
    )
    .replace(
      /Enforce MFA, lockout rules, and monitoring for suspicious authentication attempts\./g,
      "MFA, нэвтрэх оролдлогын түгжих дүрэм болон сэжигтэй нэвтрэлтийн хяналтыг хэрэгжүүлнэ.",
    )
    .replace(
      /Enforce MFA for all accounts; implement adaptive authentication\./g,
      "Бүх бүртгэлд MFA-г албажуулж, эрсдэлд суурилсан баталгаажуулалт хэрэгжүүлнэ.",
    )
    .replace(
      /Enforce phishing-resistant MFA \(passkeys\/FIDO2\); monitor for anomalous logins\./g,
      "Фишингт тэсвэртэй MFA (passkey/FIDO2) хэрэгжүүлж, хэвийн бус нэвтрэлтийг хянана.",
    );
};

const translateVulnerabilityText = (
  value: string | null | undefined,
  assetName?: string | null,
) => {
  if (!value) return value;

  let text = value
    .replace(
      /MFA gap exposes (.+?) to (.+)$/i,
      (_, asset: string, threat: string) =>
        `${asset}-д MFA идэвхжээгүй тул ${translateThreatPhrase(
          threat,
        )} эрсдэл нэмэгдсэн`,
    )
    .replace(
      /MFA not enabled on (.+)$/i,
      (_, asset: string) => `${asset}-д MFA идэвхжээгүй байна`,
    )
    .replace(
      /(.+?) дээр MFA идэвхгүй тул ([^.]+?) эрсдэл нэмэгдсэн/g,
      (_, asset: string, threat: string) =>
        `${asset}-д MFA идэвхжээгүй тул ${translateThreatPhrase(
          threat,
        )} эрсдэл нэмэгдсэн`,
    )
    .replace(
      /Missing encryption enables (.+?) on (.+)$/i,
      (_, threat: string, asset: string) =>
        `${asset} дээр шифрлэлт байхгүй тул ${translateThreatPhrase(
          threat,
        )} эрсдэл нэмэгдсэн`,
    )
    .replace(
      /Encryption not enabled on (.+)$/i,
      (_, asset: string) => `${asset} дээр шифрлэлт идэвхжээгүй байна`,
    )
    .replace(
      /Backup gap increases (.+?) impact on (.+)$/i,
      (_, threat: string, asset: string) =>
        `${asset} дээр нөөцлөлтгүй тул ${translateThreatPhrase(
          threat,
        )} нөлөөлөл нэмэгдэнэ`,
    )
    .replace(
      /No backups configured for (.+)$/i,
      (_, asset: string) => `${asset} дээр нөөцлөлт тохируулаагүй байна`,
    )
    .replace(
      /Insufficient logging limits detection of (.+?) on (.+)$/i,
      (_, threat: string, asset: string) =>
        `${asset} дээр лог бүртгэл дутуу тул ${translateThreatPhrase(
          threat,
        )} илрүүлэх боломж хязгаарлагдана`,
    )
    .replace(
      /Insufficient logging on (.+)$/i,
      (_, asset: string) => `${asset} дээр лог бүртгэл дутуу байна`,
    );

  text = text
    .replace(
      /Authentication is password-only\./g,
      "Нэвтрэлт зөвхөн нууц үгээр хийгдэж байна.",
    )
    .replace(
      /Multi-factor authentication is disabled\./g,
      "Олон хүчин зүйлийн баталгаажуулалт (MFA) идэвхгүй байна.",
    )
    .replace(
      /Asset is internet-exposed, which dramatically raises the risk of credential-based compromise\./g,
      "Хөрөнгө интернетэд нээлттэй тул нэвтрэх эрхийн мэдээлэл ашиглан халдах эрсдэл эрс нэмэгдэнэ.",
    )
    .replace(
      /Without MFA, a compromised password is enough for an attacker to gain access\./g,
      "MFA байхгүй үед нууц үг алдагдвал халдагч системд нэвтрэх боломжтой.",
    )
    .replace(
      /Data on this asset is not encrypted/g,
      "Энэ хөрөнгө дээрх өгөгдөл шифрлэгдээгүй байна",
    )
    .replace(/classification:/g, "мэдээллийн ангилал:")
    .replace(
      /Sensitive data should be encrypted at rest and in transit\./g,
      "Нууц болон мэдрэмтгий өгөгдлийг хадгалах болон дамжуулах үед шифрлэх шаардлагатай.",
    )
    .replace(
      /Backups are not enabled, leaving the asset vulnerable to ransomware, accidental deletion, and disaster scenarios\./g,
      "Нөөцлөлт идэвхгүй байгаа тул ransomware, санамсаргүй устгал, системийн доголдлын үед сэргээх боломж сул байна.",
    )
    .replace(
      /Security events are not being collected or shipped to a SIEM\. Without logs, attacks cannot be detected or investigated\./g,
      "Аюулгүй байдлын үйл явдлын лог цуглуулагдахгүй эсвэл SIEM рүү илгээгдэхгүй байна. Логгүй үед халдлагыг цаг тухайд нь илрүүлэх, шалгах боломж хязгаарлагдана.",
    )
    .replace(/Related mapped threat: ([^.]+)\./g, (_, threat: string) => {
      return `Холбогдох аюул занал: ${translateThreatPhrase(threat)}.`;
    })
    .replace(/Холбогдох аюул занал: ([^.]+)\./g, (_, threat: string) => {
      return `Холбогдох аюул занал: ${translateThreatPhrase(threat)}.`;
    })
    .replace(
      /No specific mapped threat was linked to this finding\./g,
      "Тодорхой аюул занал холбогдоогүй.",
    );

  return assetName ? text.replaceAll("this asset", assetName) : text;
};

export default function ThreatLibraryPage() {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [filterRisk, setFilterRisk] = useState(ALL);
  const [filterType, setFilterType] = useState(ALL);
  const [filterAsset, setFilterAsset] = useState(ALL);
  const [page, setPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [selectedThreat, setSelectedThreat] = useState<ThreatTableRow | null>(
    null,
  );

  // Vulnerability state
  const [vulns, setVulns] = useState<Vulnerability[]>([]);

  useEffect(() => {
    let mounted = true;

    const loadThreatsAndVulnerabilities = async () => {
      const threatRes = await fetch("/api/threats/library");
      if (!threatRes.ok) throw new Error("Failed to fetch threats");

      await fetch("/api/vulnerabilities/scan", { method: "POST" }).catch(
        (scanError) => {
          console.error("Automatic vulnerability sync failed:", scanError);
        },
      );

      const vulnRes = await fetch("/api/vulnerabilities");
      return Promise.all([
        threatRes.json(),
        vulnRes.ok ? vulnRes.json() : Promise.resolve({ vulnerabilities: [] }),
      ]);
    };

    loadThreatsAndVulnerabilities()
      .then(([threatData, vulnData]) => {
        if (!mounted) return;
        setThreats(threatData.threats || []);
        setVulns(vulnData.vulnerabilities || []);
        setError("");
      })
      .catch(() => {
        if (!mounted) return;
        setThreats([]);
        setError("Аюулын мэдээлэл ачаалах үед алдаа гарлаа.");
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });

    return () => {
      mounted = false;
    };
  }, []);

  const threatTypes = useMemo(() => {
    const types = new Set(
      threats.map((threat) => threat.threat_type).filter(Boolean),
    );
    return [ALL, ...Array.from(types).sort()] as string[];
  }, [threats]);

  const assetOptions = useMemo(() => {
    const assets = new Map<number, LinkedAsset>();
    for (const threat of threats) {
      for (const asset of threat.linked_assets) {
        assets.set(asset.id, asset);
      }
    }
    return Array.from(assets.values()).sort((a, b) =>
      a.asset_name.localeCompare(b.asset_name),
    );
  }, [threats]);

  const activeVulns = useMemo(
    () =>
      vulns.filter((v) => v.status === "open" || v.status === "in_progress"),
    [vulns],
  );

  const uniqueVulns = useMemo(() => {
    const seen = new Set<string>();
    return activeVulns.filter((v) => {
      const key = [
        v.asset_id ?? 0,
        v.threat_id ?? 0,
        v.cve_id ?? "",
        v.title.trim().toLowerCase(),
      ].join("|");
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [activeVulns]);

  const stats = useMemo(() => {
    const uniqueThreatIds = new Set<number>();
    const affectedAssetIds = new Set<number>();
    for (const v of uniqueVulns) {
      if (v.threat_id != null) uniqueThreatIds.add(v.threat_id);
      if (v.asset_id != null) affectedAssetIds.add(v.asset_id);
    }
    return {
      vulnThreats: uniqueThreatIds.size,
      totalVulns: uniqueVulns.length,
      affectedAssets: affectedAssetIds.size,
    };
  }, [uniqueVulns]);

  const threatDetailsById = useMemo(() => {
    const map = new Map<number, Threat>();
    for (const threat of threats) map.set(threat.id, threat);
    return map;
  }, [threats]);

  const assetDetailsById = useMemo(() => {
    const map = new Map<number, LinkedAsset>();
    for (const threat of threats) {
      for (const asset of threat.linked_assets) {
        if (!map.has(asset.id)) map.set(asset.id, asset);
      }
    }
    for (const vuln of uniqueVulns) {
      if (vuln.asset_id == null || map.has(vuln.asset_id)) continue;
      map.set(vuln.asset_id, {
        id: vuln.asset_id,
        asset_name: vuln.asset_name ?? `Хөрөнгө #${vuln.asset_id}`,
        asset_code: null,
        asset_type: null,
        criticality: null,
        internet_exposed: false,
        status: null,
        risk_level: "Unknown",
        matched_asset_type: "",
      });
    }
    return map;
  }, [threats, uniqueVulns]);

  const threatRows = useMemo(() => {
    const grouped = new Map<
      string,
      { assetId: number; threatId: number; vulns: Vulnerability[] }
    >();

    for (const vuln of uniqueVulns) {
      if (vuln.asset_id == null || vuln.threat_id == null) continue;
      const key = `${vuln.asset_id}-${vuln.threat_id}`;
      const group =
        grouped.get(key) ??
        ({
          assetId: vuln.asset_id,
          threatId: vuln.threat_id,
          vulns: [],
        } satisfies {
          assetId: number;
          threatId: number;
          vulns: Vulnerability[];
        });
      group.vulns.push(vuln);
      grouped.set(key, group);
    }

    const q = search.trim().toLowerCase();
    const rows: ThreatTableRow[] = [];

    for (const group of grouped.values()) {
      const firstVuln = group.vulns[0];
      const threat = threatDetailsById.get(group.threatId);
      const asset = assetDetailsById.get(group.assetId) ?? {
        id: group.assetId,
        asset_name: firstVuln.asset_name ?? `Хөрөнгө #${group.assetId}`,
        asset_code: null,
        asset_type: null,
        criticality: null,
        internet_exposed: false,
        status: null,
        risk_level: "Unknown",
        matched_asset_type: "",
      };
      const riskLevel = group.vulns.reduce<ThreatTableRow["risk_level"]>(
        (current, vuln) =>
          severityWeight(vuln.severity) > severityWeight(current)
            ? vuln.severity
            : current,
        "Low",
      );
      const threatName =
        threat?.threat_name ??
        firstVuln.threat_name ??
        `Аюул #${group.threatId}`;
      const threatType = threat?.threat_type ?? firstVuln.threat_type ?? null;
      const description =
        threat?.description_mn ??
        threat?.description ??
        firstVuln.threat_description ??
        null;
      const mitigation = translateMitigationText(
        threat?.mitigation_notes_mn ??
          threat?.mitigation_notes ??
          firstVuln.threat_mitigation_notes_mn ??
          firstVuln.threat_mitigation_notes ??
          firstVuln.remediation_notes ??
          null,
      );

      const searchable = [
        threatName,
        threatType,
        asset.asset_name,
        asset.asset_code,
        asset.asset_type,
        description,
        ...group.vulns.map((vuln) => vuln.title),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      if (q && !searchable.includes(q)) continue;
      if (filterRisk !== ALL && riskLevel !== filterRisk) continue;
      if (filterType !== ALL && threatType !== filterType) continue;
      if (filterAsset !== ALL && String(asset.id) !== filterAsset) continue;

      rows.push({
        key: `${group.assetId}-${group.threatId}`,
        threat_id: group.threatId,
        threat_name: threatName,
        threat_type: threatType,
        description,
        mitigation,
        risk_level: riskLevel,
        asset,
        vulnerabilities: group.vulns.sort(
          (a, b) =>
            severityWeight(b.severity) - severityWeight(a.severity) ||
            a.title.localeCompare(b.title),
        ),
        openCount: group.vulns.filter(
          (vuln) => vuln.status === "open" || vuln.status === "in_progress",
        ).length,
        criticalCount: group.vulns.filter(
          (vuln) => vuln.severity === "Critical",
        ).length,
      });
    }

    return rows.sort(
      (a, b) =>
        severityWeight(b.risk_level) - severityWeight(a.risk_level) ||
        a.threat_name.localeCompare(b.threat_name) ||
        a.asset.asset_name.localeCompare(b.asset.asset_name),
    );
  }, [
    assetDetailsById,
    filterAsset,
    filterRisk,
    filterType,
    search,
    threatDetailsById,
    uniqueVulns,
  ]);

  const pageCount = Math.max(1, Math.ceil(threatRows.length / rowsPerPage));
  const currentPage = Math.min(page, pageCount);
  const visibleThreatRows = threatRows.slice(
    (currentPage - 1) * rowsPerPage,
    currentPage * rowsPerPage,
  );
  const quickTypeFilters = threatTypes.slice(0, 8);

  const hasActiveFilters =
    search.trim() !== "" ||
    filterRisk !== ALL ||
    filterType !== ALL ||
    filterAsset !== ALL;

  const resetFilters = () => {
    setSearch("");
    setFilterRisk(ALL);
    setFilterType(ALL);
    setFilterAsset(ALL);
    setPage(1);
  };

  return (
    <div className="app-page p-4 sm:p-6 md:p-8 pb-8">
      <div className="mx-auto max-w-7xl">
        <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">
              Хөрөнгүүдэд үүсч болзошгүй аюулууд
            </h1>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Link
              href="/assets"
              className="inline-flex h-9 items-center justify-center gap-2 rounded-md border border-border bg-background px-3 text-sm font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground"
            >
              <Database className="size-4" />
              Хөрөнгө харах
            </Link>
          </div>
        </div>

        {!loading && (
          <div className="mb-5 grid grid-cols-1 gap-3 sm:grid-cols-3">
            {[
              {
                label: "Аюулын тоо",
                value: stats.vulnThreats,
                icon: ShieldAlert,
                color: "text-blue-700 dark:text-blue-300",
                surface:
                  "border-blue-200 bg-blue-50 dark:border-blue-900/60 dark:bg-blue-950/30",
              },
              {
                label: "Эмзэг байдал",
                value: stats.totalVulns,
                icon: Bug,
                color: "text-rose-700 dark:text-rose-300",
                surface:
                  "border-rose-200 bg-rose-50 dark:border-rose-900/60 dark:bg-rose-950/30",
              },
              {
                label: "Холбогдсон хөрөнгө",
                value: stats.affectedAssets,
                icon: Database,
                color: "text-orange-700 dark:text-orange-300",
                surface:
                  "border-orange-200 bg-orange-50 dark:border-orange-900/60 dark:bg-orange-950/30",
              },
            ].map(({ label, value, icon: Icon, color, surface }) => (
              <div key={label} className={`rounded-lg border p-4 ${surface}`}>
                <div className="mb-3 flex items-center justify-between gap-3">
                  <span className="text-xs font-semibold uppercase text-muted-foreground">
                    {label}
                  </span>
                  <Icon className={`size-4 ${color}`} />
                </div>
                <div className={`text-2xl font-bold ${color}`}>{value}</div>
              </div>
            ))}
          </div>
        )}

        <div className="mb-5 rounded-lg border border-border bg-card p-3 shadow-sm">
          <div className="flex flex-col gap-3 lg:flex-row">
            <div className="relative min-w-0 flex-1">
              <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <input
                type="text"
                placeholder="Аюул, хөрөнгө хайх..."
                value={search}
                onChange={(event) => {
                  setSearch(event.target.value);
                  setPage(1);
                }}
                className="app-form-field h-10 w-full rounded-md border pl-9 pr-4 text-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
              />
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 lg:flex lg:shrink-0">
              <label className="relative">
                <Filter className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                <select
                  value={filterRisk}
                  onChange={(event) => {
                    setFilterRisk(event.target.value);
                    setPage(1);
                  }}
                  className="app-form-field h-10 w-full rounded-md border pl-9 pr-8 text-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 lg:w-40"
                >
                  {[ALL, "Critical", "High", "Medium", "Low"].map((value) => (
                    <option key={value} value={value}>
                      {value === ALL ? "Бүх эрсдэл" : riskLabel(value)}
                    </option>
                  ))}
                </select>
              </label>
              <select
                value={filterType}
                onChange={(event) => {
                  setFilterType(event.target.value);
                  setPage(1);
                }}
                className="app-form-field h-10 w-full rounded-md border px-3 text-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 lg:w-44"
              >
                {threatTypes.map((value) => (
                  <option key={value} value={value}>
                    {value === ALL ? "Бүх төрөл" : threatTypeLabel(value)}
                  </option>
                ))}
              </select>
              <select
                value={filterAsset}
                onChange={(event) => {
                  setFilterAsset(event.target.value);
                  setPage(1);
                }}
                className="app-form-field h-10 w-full rounded-md border px-3 text-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 lg:w-56"
              >
                <option value={ALL}>Бүх хөрөнгө</option>
                {assetOptions.map((asset) => (
                  <option key={asset.id} value={String(asset.id)}>
                    {asset.asset_name}
                  </option>
                ))}
              </select>
            </div>
            <button
              type="button"
              onClick={resetFilters}
              disabled={!hasActiveFilters}
              className="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-border px-3 text-sm font-medium text-muted-foreground transition hover:bg-accent hover:text-accent-foreground disabled:pointer-events-none disabled:opacity-40"
            >
              <RotateCcw className="size-4" />
              Цэвэрлэх
            </button>
          </div>
        </div>

        {loading ? (
          <div className="rounded-lg border border-border bg-card p-4 shadow-sm">
            <div className="space-y-2">
              {[0, 1, 2, 3, 4].map((item) => (
                <div
                  key={item}
                  className="h-12 animate-pulse rounded-md bg-muted/60"
                />
              ))}
            </div>
          </div>
        ) : error ? (
          <div className="flex min-h-64 flex-col items-center justify-center rounded-lg border border-border bg-card px-4 text-center text-muted-foreground">
            <AlertTriangle className="mb-3 size-10 text-orange-500" />
            <p className="text-sm">{error}</p>
          </div>
        ) : threatRows.length === 0 ? (
          <div className="flex min-h-64 flex-col items-center justify-center rounded-lg border border-border bg-card px-4 text-center text-muted-foreground">
            <AlertTriangle className="mb-3 size-10 opacity-50" />
            <p className="text-sm">Сонгосон нөхцөлд тохирох аюул олдсонгүй.</p>
          </div>
        ) : (
          <section className="overflow-hidden rounded-lg border border-border bg-card shadow-sm">
            <div className="border-b border-border p-4">
              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div>
                  <h2 className="text-base font-bold">Аюулын жагсаалт</h2>
                </div>
                <span className="rounded-full bg-muted px-3 py-1 text-xs font-semibold text-muted-foreground">
                  Нийт {threatRows.length} аюул
                </span>
              </div>
            </div>

            <div>
              <div>
                <div className="grid grid-cols-[1.2fr_0.8fr_1.1fr_0.6fr_88px] border-b border-border bg-muted/40 px-4 py-3 text-[11px] font-bold uppercase tracking-wide text-muted-foreground">
                  <span>Аюул</span>
                  <span>Төрөл</span>
                  <span>Нөлөөлөх хөрөнгө</span>
                  <span>Эрсдэлийн түвшин</span>
                  <span>Үйлдэл</span>
                </div>
                {visibleThreatRows.map((row) => (
                  <div
                    key={row.key}
                    className="grid grid-cols-[1.2fr_0.8fr_1.1fr_0.6fr_88px] items-center gap-2 border-b border-border px-4 py-3 text-sm last:border-b-0 hover:bg-slate-50 dark:hover:bg-slate-900/40"
                  >
                    <div className="flex min-w-0 items-center gap-3">
                      <span
                        className={`h-8 w-1 shrink-0 rounded-full ${getRiskAccent(row.risk_level)}`}
                      />
                      <span className="truncate font-bold">
                        {row.threat_name}
                      </span>
                    </div>
                    <p className="line-clamp-2 text-xs leading-5 text-slate-600 dark:text-slate-300">
                      {threatTypeLabel(row.threat_type) || "—"}
                    </p>
                    <span className="inline-flex min-w-0 items-center gap-2">
                      <Database className="size-4 shrink-0 text-blue-600" />
                      <span className="truncate">{row.asset.asset_name}</span>
                    </span>
                    <span
                      className={`w-fit rounded-full border px-2.5 py-1 text-xs font-bold ${getRiskColor(row.risk_level)}`}
                    >
                      {riskLabel(row.risk_level)}
                    </span>
                    <button
                      type="button"
                      onClick={() => setSelectedThreat(row)}
                      className="inline-flex h-8 items-center justify-center rounded-md border border-blue-500 px-3 text-xs font-bold text-blue-600 transition hover:bg-blue-50 dark:text-blue-300 dark:hover:bg-blue-950/30"
                    >
                      Дэлгэрэнгүй
                    </button>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex flex-col gap-3 border-t border-border px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
              <span className="text-xs text-muted-foreground">
                Нийт {threatRows.length} аюул
              </span>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => setPage((current) => Math.max(1, current - 1))}
                  disabled={currentPage === 1}
                  className="inline-flex size-8 items-center justify-center rounded-md border border-border transition hover:bg-accent disabled:pointer-events-none disabled:opacity-40"
                >
                  <ChevronLeft className="size-4" />
                </button>
                {Array.from({ length: pageCount }, (_, index) => index + 1)
                  .filter(
                    (pageNumber) =>
                      pageNumber === 1 ||
                      pageNumber === pageCount ||
                      Math.abs(pageNumber - currentPage) <= 1,
                  )
                  .map((pageNumber, index, pages) => (
                    <span key={pageNumber} className="inline-flex items-center">
                      {index > 0 && pageNumber - pages[index - 1] > 1 && (
                        <span className="px-1 text-xs text-muted-foreground">
                          ...
                        </span>
                      )}
                      <button
                        type="button"
                        onClick={() => setPage(pageNumber)}
                        className={`inline-flex size-8 items-center justify-center rounded-md border text-xs font-bold transition ${
                          currentPage === pageNumber
                            ? "border-blue-600 bg-blue-600 text-white"
                            : "border-border hover:bg-accent"
                        }`}
                      >
                        {pageNumber}
                      </button>
                    </span>
                  ))}
                <button
                  type="button"
                  onClick={() =>
                    setPage((current) => Math.min(pageCount, current + 1))
                  }
                  disabled={currentPage === pageCount}
                  className="inline-flex size-8 items-center justify-center rounded-md border border-border transition hover:bg-accent disabled:pointer-events-none disabled:opacity-40"
                >
                  <ChevronRight className="size-4" />
                </button>
                <select
                  value={rowsPerPage}
                  onChange={(event) => {
                    setRowsPerPage(Number(event.target.value));
                    setPage(1);
                  }}
                  className="app-form-field h-8 rounded-md border px-2 text-xs outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
                >
                  {[10, 25, 50].map((value) => (
                    <option key={value} value={value}>
                      {value} / хуудас
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </section>
        )}

        {selectedThreat &&
          typeof document !== "undefined" &&
          createPortal(
            <ThreatDetailsModal
              threat={selectedThreat}
              onClose={() => setSelectedThreat(null)}
            />,
            document.body,
          )}
      </div>
    </div>
  );
}

function ThreatDetailsModal({
  threat,
  onClose,
}: {
  threat: ThreatTableRow;
  onClose: () => void;
}) {
  return (
    <div className="fixed inset-0 z-9999 flex items-center justify-center bg-slate-950/65 p-4">
      <div
        role="dialog"
        aria-modal="true"
        aria-label={`${threat.threat_name} дэлгэрэнгүй`}
        className="max-h-[90vh] w-full max-w-3xl overflow-hidden rounded-lg border border-slate-200 bg-white text-slate-950 shadow-xl dark:border-slate-800 dark:bg-slate-950 dark:text-slate-50"
      >
        <div className="flex items-start justify-between gap-4 border-b border-border p-5">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`rounded-full border px-2.5 py-1 text-xs font-bold ${getRiskColor(threat.risk_level)}`}
              >
                {riskLabel(threat.risk_level)}
              </span>
            </div>
            <h2 className="mt-3 text-xl font-bold leading-tight">
              {threat.threat_name}
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">
              {threatTypeLabel(threat.threat_type)}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="inline-flex size-9 shrink-0 items-center justify-center rounded-md border border-border transition hover:bg-accent hover:text-accent-foreground"
            aria-label="Хаах"
          >
            <X className="size-4" />
          </button>
        </div>

        <div className="max-h-[calc(90vh-104px)] overflow-y-auto p-5">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-md border border-border bg-muted/30 p-3">
              <p className="text-[11px] font-bold uppercase text-muted-foreground">
                Нөлөөлөх хөрөнгө
              </p>
              <p className="mt-1 font-semibold">{threat.asset.asset_name}</p>
              <p className="mt-1 text-xs text-muted-foreground">
                {[
                  threat.asset.asset_code,
                  assetTypeLabel(threat.asset.asset_type),
                ]
                  .filter(Boolean)
                  .join(" · ") || "—"}
              </p>
            </div>
            <div className="rounded-md border border-border bg-muted/30 p-3">
              <p className="text-[11px] font-bold uppercase text-muted-foreground">
                Хөрөнгийн төлөв
              </p>
              <div className="mt-1 flex flex-wrap gap-2">
                <span
                  className={`rounded-full px-2 py-1 text-xs font-semibold ${getCriticalityColor(
                    threat.asset.criticality,
                  )}`}
                >
                  {criticalityLabel(threat.asset.criticality)}
                </span>
                {threat.asset.status && (
                  <span className="rounded-full border border-border px-2 py-1 text-xs font-semibold">
                    {statusLabel(threat.asset.status)}
                  </span>
                )}
                {threat.asset.internet_exposed && (
                  <span className="rounded-full bg-orange-100 px-2 py-1 text-xs font-semibold text-orange-700 dark:bg-orange-950/50 dark:text-orange-300">
                    Интернэтэд нээлттэй
                  </span>
                )}
              </div>
            </div>
          </div>

          {threat.description && (
            <section className="mt-5">
              <h3 className="text-sm font-bold">Аюулын тайлбар</h3>
              <p className="mt-2 text-sm leading-6 text-muted-foreground">
                {threat.description}
              </p>
            </section>
          )}

          {threat.mitigation && (
            <section className="mt-5 rounded-md border border-blue-200 bg-blue-50/60 p-4 dark:border-blue-900/60 dark:bg-blue-950/20">
              <h3 className="text-sm font-bold text-blue-800 dark:text-blue-200">
                Зөвлөмж
              </h3>
              <p className="mt-2 text-sm leading-6 text-blue-900/80 dark:text-blue-100/80">
                {threat.mitigation}
              </p>
            </section>
          )}

          <section className="mt-5">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <h3 className="text-sm font-bold">Холбогдсон эмзэг байдал</h3>
              <span className="rounded-full bg-muted px-2.5 py-1 text-xs font-semibold text-muted-foreground">
                {threat.openCount} нээлттэй / {threat.vulnerabilities.length}{" "}
                нийт
              </span>
            </div>
            <div className="space-y-2">
              {threat.vulnerabilities.map((vuln) => (
                <div
                  key={vuln.id}
                  className="rounded-md border border-border bg-background p-3"
                >
                  <div className="mb-2 flex flex-wrap items-center gap-1.5">
                    <span
                      className={`rounded border px-2 py-0.5 text-[11px] font-bold ${VULN_SEVERITY_STYLES[vuln.severity]}`}
                    >
                      {VULN_SEVERITY_LABEL[vuln.severity]}
                    </span>
                    <span
                      className={`rounded border px-2 py-0.5 text-[11px] font-medium ${VULN_STATUS_STYLES[vuln.status]}`}
                    >
                      {VULN_STATUS_LABEL[vuln.status]}
                    </span>
                    {vuln.cve_id && (
                      <span className="font-mono text-[11px] text-muted-foreground">
                        {vuln.cve_id}
                      </span>
                    )}
                    {vuln.cvss_score && (
                      <span className="font-mono text-[11px] text-muted-foreground">
                        CVSS {vuln.cvss_score}
                      </span>
                    )}
                  </div>
                  <p className="text-sm font-semibold">
                    {translateVulnerabilityText(vuln.title, vuln.asset_name)}
                  </p>
                  {vuln.description && (
                    <p className="mt-1 text-xs leading-5 text-muted-foreground">
                      {translateVulnerabilityText(
                        vuln.description,
                        vuln.asset_name,
                      )}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
