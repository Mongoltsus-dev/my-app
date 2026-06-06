"use client";

import { useAuth } from "@/app/context/AuthContext";
import AddAssetModal from "@/components/assets/AddAssetModal";
import ImportAssetsModal from "@/components/assets/ImportAssetsModal";
import {
  ACCESS_LEVEL_LABELS,
  ACCESS_LEVEL_OPTIONS,
  ASSET_DETAIL_OPTION_LABELS,
  ASSET_TYPE_LABELS,
  ASSET_TYPE_METADATA,
  ASSET_TYPE_OPTIONS,
  AUTHENTICATION_METHOD_LABELS,
  AUTHENTICATION_METHOD_OPTIONS,
  CRITICALITY_LABELS,
  CRITICALITY_LEVELS,
  DATA_CLASSIFICATION_LABELS,
  DATA_CLASSIFICATION_OPTIONS,
  HOSTING_LABELS,
  RISK_LEVEL_LABELS,
  STATUS_LABELS,
  STATUS_OPTIONS,
  getHostingOptions,
  getLabel,
} from "@/components/assets/asset-constants";
import {
  AlertTriangle,
  BarChart3,
  Building2,
  Cloud,
  Database,
  FileText,
  Filter,
  Globe2,
  HardDrive,
  KeyRound,
  Layers,
  LockKeyhole,
  Network,
  Pencil,
  RotateCcw,
  Save,
  Search,
  Server,
  ShieldAlert,
  Users,
  X,
  type LucideIcon,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState, type FormEvent } from "react";

type AssetDetails = Record<
  string,
  string | number | boolean | null | undefined
>;

interface CriticalBusinessProcess {
  id: number;
  process_code?: string | null;
  process_name: string;
  criticality?: string | null;
  status?: string | null;
  dependency_type?: string | null;
}

interface Asset {
  id?: string | number;
  asset_type_id?: number;
  asset_type?: string;
  owner_id?: number;
  asset_name: string;
  asset_code: string;
  business_owner?: string;
  technical_owner?: string;
  department?: string;
  data_classification?: string;
  access_level?: string;
  authentication_method?: string;
  supports_critical_service?: boolean;
  business_process_ids?: number[];
  critical_business_processes?: CriticalBusinessProcess[];
  hosting?: string;
  region?: string;
  country?: string;
  key_users_customers?: string;
  rto_hours?: number | string;
  rpo_hours?: number | string;
  criticality: string;
  internet_exposed?: boolean;
  backup_enabled?: boolean;
  encryption_enabled?: boolean;
  mfa_enabled?: boolean;
  logging_enabled?: boolean;
  edr_enabled?: boolean;
  vuln_scanning_enabled?: boolean;
  cmdb_ci_id?: string;
  notes?: string;
  asset_details?: AssetDetails;
  status?: string;
  created_at?: string;
  updated_at?: string;
}

const ALL = "Бүх хөрөнгө";
const ANY = "any";

const TYPE_COLORS = [
  "#2563eb",
  "#14b8a6",
  "#a855f7",
  "#f97316",
  "#22c55e",
  "#ec4899",
  "#64748b",
  "#eab308",
  "#06b6d4",
  "#ef4444",
  "#8b5cf6",
  "#10b981",
  "#f59e0b",
  "#475569",
];

const isCriticalAsset = (asset: Asset) =>
  asset.criticality?.includes("Tier 0") ||
  asset.criticality?.includes("Tier 1");

const isSensitiveAsset = (asset: Asset) =>
  ["Confidential", "Restricted"].includes(asset.data_classification ?? "") ||
  getCanonicalAssetType(asset.asset_type) === "Information / Data Asset";

const LEGACY_ASSET_TYPE_MAP: Record<string, string> = {
  Application: "Software Asset",
  Service: "Service Asset",
  Database: "Information / Data Asset",
  Network: "Network / Communication Asset",
  "Endpoint Fleet": "Hardware Asset",
  Identity: "Identity / Access Asset",
  "Identity Provider": "Identity / Access Asset",
  "SaaS Tenant": "Cloud / Virtual Asset",
  "Business Process": "Business Process Asset",
  "Third Party Service": "Third-Party / Supplier Asset",
  "Backup System": "System / Platform",
  Facility: "Physical / Facility Asset",
  "Data Asset": "Information / Data Asset",
  "Medical Device": "Hardware Asset",
  API: "Service Asset",
  Infrastructure: "System / Platform",
  "Message Queue": "System / Platform",
  "Cache System": "System / Platform",
  "File Storage": "Information / Data Asset",
  "Monitoring/Logging": "System / Platform",
  "VPN/Remote Access": "Network / Communication Asset",
  "Load Balancer": "Network / Communication Asset",
  "Container Orchestration": "Cloud / Virtual Asset",
  "Web Server": "System / Platform",
  "Email System": "System / Platform",
  "Collaboration Platform": "System / Platform",
  Hardware: "Hardware Asset",
  Software: "Software Asset",
  Data: "Information / Data Asset",
  Cloud: "Cloud / Virtual Asset",
};

const getCanonicalAssetType = (assetType?: string | null) => {
  if (!assetType) return "";
  if (ASSET_TYPE_METADATA[assetType]) return assetType;
  return LEGACY_ASSET_TYPE_MAP[assetType] ?? assetType;
};

const getAssetDetails = (asset: Asset): AssetDetails =>
  asset.asset_details && typeof asset.asset_details === "object"
    ? asset.asset_details
    : {};

const getDetailValue = (asset: Asset, key: string) => {
  const value = getAssetDetails(asset)[key];
  if (value === undefined || value === null || value === "") return "";
  return String(value);
};

const getAssetSubtype = (asset: Asset) =>
  getLabel(
    ASSET_DETAIL_OPTION_LABELS,
    getDetailValue(asset, "asset_subtype"),
  ) ||
  (asset.asset_type &&
  asset.asset_type !== getCanonicalAssetType(asset.asset_type)
    ? getLabel(ASSET_TYPE_LABELS, asset.asset_type)
    : getLabel(ASSET_TYPE_LABELS, getCanonicalAssetType(asset.asset_type))) ||
  "Ангилагдаагүй";

const getAssetIcon = (assetType?: string): LucideIcon => {
  switch (getCanonicalAssetType(assetType)) {
    case "Information / Data Asset":
      return Database;
    case "Hardware Asset":
      return HardDrive;
    case "Software Asset":
      return Layers;
    case "System / Platform":
      return Server;
    case "Network / Communication Asset":
      return Network;
    case "Cloud / Virtual Asset":
      return Cloud;
    case "Identity / Access Asset":
      return KeyRound;
    case "People / Human Asset":
      return Users;
    case "Business Process Asset":
      return BarChart3;
    case "Service Asset":
      return Globe2;
    case "Physical / Facility Asset":
      return Building2;
    case "Documentation / Knowledge Asset":
      return FileText;
    case "Third-Party / Supplier Asset":
      return Users;
    case "Legal / Financial / Reputation Asset":
      return ShieldAlert;
    default:
      return Layers;
  }
};

const criticalityClass = (criticality?: string) => {
  if (criticality?.includes("Tier 0"))
    return "border-red-200 bg-red-50 text-red-700";
  if (criticality?.includes("Tier 1"))
    return "border-orange-200 bg-orange-50 text-orange-700";
  if (criticality?.includes("Tier 2"))
    return "border-amber-200 bg-amber-50 text-amber-700";
  return "border-emerald-200 bg-emerald-50 text-emerald-700";
};

const shortCriticalityLabel = (criticality?: string) => {
  if (criticality?.includes("Tier 0")) return "Түвшин 0";
  if (criticality?.includes("Tier 1")) return "Түвшин 1";
  if (criticality?.includes("Tier 2")) return "Түвшин 2";
  if (criticality?.includes("Tier 3")) return "Түвшин 3";
  return criticality || "—";
};

const statusClass = (status?: string) => {
  if (status === "Active")
    return "border-emerald-200 bg-emerald-50 text-emerald-700";
  if (status === "Deprecated") return "border-red-200 bg-red-50 text-red-700";
  if (status === "Inactive")
    return "border-slate-200 bg-slate-100 text-slate-600";
  return "border-blue-200 bg-blue-50 text-blue-700";
};

const dataClass = (classification?: string) => {
  if (classification === "Restricted")
    return "border-purple-200 bg-purple-50 text-purple-700";
  if (classification === "Confidential")
    return "border-blue-200 bg-blue-50 text-blue-700";
  if (classification === "Internal")
    return "border-slate-200 bg-slate-100 text-slate-700";
  return "border-emerald-200 bg-emerald-50 text-emerald-700";
};

const riskSignalCount = (asset: Asset) =>
  [
    isCriticalAsset(asset),
    asset.internet_exposed,
    isSensitiveAsset(asset),
    !asset.mfa_enabled &&
      [
        "Identity / Access Asset",
        "System / Platform",
        "Service Asset",
      ].includes(getCanonicalAssetType(asset.asset_type)),
    !asset.backup_enabled &&
      [
        "Information / Data Asset",
        "System / Platform",
        "Cloud / Virtual Asset",
      ].includes(getCanonicalAssetType(asset.asset_type)),
    getCanonicalAssetType(asset.asset_type) === "Third-Party / Supplier Asset",
  ].filter(Boolean).length;

const riskLevel = (asset: Asset) => {
  const score = riskSignalCount(asset);
  if (score >= 4 || (asset.internet_exposed && isCriticalAsset(asset))) {
    return "High";
  }
  if (score >= 2) return "Medium";
  return "Low";
};

const riskClass = (level: string) => {
  if (level === "High") return "border-red-200 bg-red-50 text-red-700";
  if (level === "Medium") return "border-amber-200 bg-amber-50 text-amber-700";
  return "border-emerald-200 bg-emerald-50 text-emerald-700";
};

type AssetFormData = {
  id: string | number;
  asset_type_id: string | number | null;
  owner_id: string;
  asset_name: string;
  asset_code: string;
  asset_type: string;
  business_owner: string;
  technical_owner: string;
  department: string;
  data_classification: string;
  access_level: string;
  authentication_method: string;
  supports_critical_service: boolean;
  business_process_ids: number[];
  hosting: string;
  country: string;
  region: string;
  key_users_customers: string;
  rto_hours: string;
  rpo_hours: string;
  criticality: string;
  internet_exposed: boolean;
  backup_enabled: boolean;
  encryption_enabled: boolean;
  mfa_enabled: boolean;
  logging_enabled: boolean;
  edr_enabled: boolean;
  vuln_scanning_enabled: boolean;
  cmdb_ci_id: string;
  notes: string;
  asset_details: Record<string, string>;
  status: string;
};

const FIELD_CLASS =
  "app-form-field h-11 w-full min-w-0 rounded-md border px-3 text-sm font-medium outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20";

const TEXTAREA_CLASS =
  "app-form-field min-h-28 w-full min-w-0 rounded-md border px-3 py-2 text-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20";

const EDIT_SECTION_CLASS =
  "rounded-lg border border-border bg-background/60 p-4 shadow-sm";

const EDIT_SECTION_TITLE_CLASS =
  "flex items-center gap-2 text-sm font-semibold text-foreground";

const EDIT_SUMMARY_ITEM_CLASS =
  "rounded-md border border-border bg-card px-3 py-2";

type SecurityControlField =
  | "internet_exposed"
  | "supports_critical_service"
  | "mfa_enabled"
  | "encryption_enabled"
  | "backup_enabled"
  | "logging_enabled"
  | "edr_enabled"
  | "vuln_scanning_enabled";

const SECURITY_CONTROL_ITEMS: Array<{
  field: SecurityControlField;
  label: string;
  risk?: boolean;
}> = [
  { field: "internet_exposed", label: "Интернэтэд нээлттэй", risk: true },
  { field: "supports_critical_service", label: "Чухал үйлчилгээг дэмждэг" },
  { field: "mfa_enabled", label: "MFA" },
  { field: "encryption_enabled", label: "Шифрлэлт" },
  { field: "backup_enabled", label: "Нөөцлөлт" },
  { field: "logging_enabled", label: "Лог бүртгэл / SIEM" },
  { field: "edr_enabled", label: "EDR" },
  { field: "vuln_scanning_enabled", label: "Эмзэг байдлын скан" },
];

const assetDetailsToForm = (details: AssetDetails) =>
  Object.fromEntries(
    Object.entries(details).map(([key, value]) => [
      key,
      value === undefined || value === null ? "" : String(value),
    ]),
  );

const toAssetFormData = (asset: Asset): AssetFormData => ({
  id: asset.id ?? "",
  asset_type_id: asset.asset_type_id ?? null,
  owner_id: asset.owner_id?.toString() ?? "",
  asset_name: asset.asset_name ?? "",
  asset_code: asset.asset_code ?? "",
  asset_type: getCanonicalAssetType(asset.asset_type) || asset.asset_type || "",
  business_owner: asset.business_owner ?? "",
  technical_owner: asset.technical_owner ?? "",
  department: asset.department ?? "",
  data_classification: asset.data_classification ?? "",
  access_level: asset.access_level ?? "",
  authentication_method: asset.authentication_method ?? "",
  supports_critical_service: Boolean(asset.supports_critical_service),
  business_process_ids: asset.business_process_ids ?? [],
  hosting: asset.hosting ?? "",
  country: asset.country ?? "",
  region: asset.region ?? "",
  key_users_customers: asset.key_users_customers ?? "",
  rto_hours: asset.rto_hours?.toString() ?? "",
  rpo_hours: asset.rpo_hours?.toString() ?? "",
  criticality: asset.criticality ?? "",
  internet_exposed: Boolean(asset.internet_exposed),
  backup_enabled: Boolean(asset.backup_enabled),
  encryption_enabled: Boolean(asset.encryption_enabled),
  mfa_enabled: Boolean(asset.mfa_enabled),
  logging_enabled: Boolean(asset.logging_enabled),
  edr_enabled: Boolean(asset.edr_enabled),
  vuln_scanning_enabled: Boolean(asset.vuln_scanning_enabled),
  cmdb_ci_id: asset.cmdb_ci_id ?? "",
  notes: asset.notes ?? "",
  asset_details: assetDetailsToForm(getAssetDetails(asset)),
  status: asset.status ?? "Active",
});

export default function AssetsPage() {
  const { user } = useAuth();
  const router = useRouter();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [activeType, setActiveType] = useState(ALL);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [criticalityFilter, setCriticalityFilter] = useState(ANY);
  const [dataFilter, setDataFilter] = useState(ANY);
  const [statusFilter, setStatusFilter] = useState(ANY);
  const [selectedAssetId, setSelectedAssetId] = useState<
    string | number | null
  >(null);
  const [assetForm, setAssetForm] = useState<AssetFormData | null>(null);
  const [assetEditorOpen, setAssetEditorOpen] = useState(false);
  const [savingAsset, setSavingAsset] = useState(false);
  const [assetSaveError, setAssetSaveError] = useState("");
  const [assetSaveMessage, setAssetSaveMessage] = useState("");

  useEffect(() => {
    if (!user) {
      router.push("/auth/login");
    }
  }, [user, router]);

  useEffect(() => {
    if (user) {
      fetchAssets();
    }
  }, [user]);

  const fetchAssets = async () => {
    try {
      const response = await fetch("/api/assets");
      if (response.ok) {
        const data = await response.json();
        setAssets(data.assets || []);
      }
    } catch (error) {
      console.error("Хөрөнгийн мэдээлэл татах үед алдаа гарлаа:", error);
      setAssets([]);
    } finally {
      setLoading(false);
    }
  };

  const stats = useMemo(() => {
    const critical = assets.filter(isCriticalAsset).length;
    const internetExposed = assets.filter(
      (asset) => asset.internet_exposed,
    ).length;
    const sensitive = assets.filter(isSensitiveAsset).length;
    const thirdParty = assets.filter(
      (asset) =>
        getCanonicalAssetType(asset.asset_type) ===
        "Third-Party / Supplier Asset",
    ).length;
    const highRisk = assets.filter(
      (asset) => riskLevel(asset) === "High",
    ).length;

    return {
      total: assets.length,
      critical,
      internetExposed,
      sensitive,
      thirdParty,
      highRisk,
    };
  }, [assets]);

  const typeCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const asset of assets) {
      const type = getCanonicalAssetType(asset.asset_type) || "Ангилагдаагүй";
      counts.set(type, (counts.get(type) ?? 0) + 1);
    }
    return counts;
  }, [assets]);

  const filteredAssets = useMemo(() => {
    const q = search.trim().toLowerCase();
    return assets.filter((asset) => {
      const details = Object.values(getAssetDetails(asset)).join(" ");
      const matchesSearch =
        !q ||
        [
          asset.asset_name,
          asset.asset_code,
          asset.asset_type,
          getAssetSubtype(asset),
          asset.department,
          asset.business_owner,
          asset.technical_owner,
          asset.data_classification,
          asset.status,
          details,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase()
          .includes(q);
      const matchesType =
        activeType === ALL ||
        getCanonicalAssetType(asset.asset_type) === activeType;
      const matchesCriticality =
        criticalityFilter === ANY || asset.criticality === criticalityFilter;
      const matchesData =
        dataFilter === ANY || asset.data_classification === dataFilter;
      const matchesStatus =
        statusFilter === ANY || asset.status === statusFilter;
      return (
        matchesSearch &&
        matchesType &&
        matchesCriticality &&
        matchesData &&
        matchesStatus
      );
    });
  }, [activeType, assets, criticalityFilter, dataFilter, search, statusFilter]);

  useEffect(() => {
    if (filteredAssets.length === 0) {
      setSelectedAssetId(null);
      return;
    }

    const stillVisible = filteredAssets.some(
      (asset) => String(asset.id) === String(selectedAssetId),
    );
    if (!stillVisible) {
      setSelectedAssetId(filteredAssets[0].id ?? null);
    }
  }, [filteredAssets, selectedAssetId]);

  const selectedAsset = useMemo(
    () =>
      filteredAssets.find(
        (asset) => String(asset.id) === String(selectedAssetId),
      ) ??
      filteredAssets[0] ??
      null,
    [filteredAssets, selectedAssetId],
  );

  useEffect(() => {
    setAssetForm(selectedAsset ? toAssetFormData(selectedAsset) : null);
    setAssetSaveError("");
    setAssetSaveMessage("");
    if (!selectedAsset) {
      setAssetEditorOpen(false);
    }
  }, [selectedAsset]);

  const selectedAssetMetadata = assetForm?.asset_type
    ? ASSET_TYPE_METADATA[assetForm.asset_type]
    : undefined;
  const selectedDetailFields = selectedAssetMetadata?.fields ?? [];

  const hasActiveFilters =
    activeType !== ALL ||
    criticalityFilter !== ANY ||
    dataFilter !== ANY ||
    statusFilter !== ANY;

  const clearFilters = () => {
    setActiveType(ALL);
    setCriticalityFilter(ANY);
    setDataFilter(ANY);
    setStatusFilter(ANY);
  };

  const updateAssetFormField = (
    field: keyof AssetFormData,
    value: string | boolean,
  ) => {
    setAssetForm((current) => {
      if (!current) return current;

      if (field === "asset_type" && typeof value === "string") {
        return {
          ...current,
          asset_type: value,
          asset_type_id: null,
          asset_details: {},
          hosting: getHostingOptions(value).includes(current.hosting)
            ? current.hosting
            : "",
        };
      }

      if (field === "access_level" && typeof value === "string") {
        return {
          ...current,
          access_level: value,
          internet_exposed: [
            "Public web access",
            "Public API exposed",
          ].includes(value),
        };
      }

      if (field === "authentication_method" && typeof value === "string") {
        return {
          ...current,
          authentication_method: value,
          mfa_enabled: [
            "Password + MFA",
            "One-Time Password (OTP)",
            "SMS OTP",
            "Email OTP",
            "Authenticator App",
            "Biometric Authentication",
            "Single Sign-On (SSO)",
            "Active Directory",
          ].includes(value),
        };
      }

      return { ...current, [field]: value };
    });
    setAssetSaveError("");
    setAssetSaveMessage("");
  };

  const toggleAssetSecurityControl = (field: SecurityControlField) => {
    setAssetForm((current) => {
      if (!current) return current;

      const enabled = !Boolean(current[field]);

      return {
        ...current,
        [field]: enabled,
        ...(field === "supports_critical_service" && !enabled
          ? { business_process_ids: [] }
          : {}),
      };
    });
    setAssetSaveError("");
    setAssetSaveMessage("");
  };

  const updateAssetDetailField = (field: string, value: string) => {
    setAssetForm((current) =>
      current
        ? {
            ...current,
            asset_details: {
              ...current.asset_details,
              [field]: value,
            },
          }
        : current,
    );
    setAssetSaveError("");
    setAssetSaveMessage("");
  };

  const resetSelectedAssetForm = () => {
    if (!selectedAsset) return;
    setAssetForm(toAssetFormData(selectedAsset));
    setAssetSaveError("");
    setAssetSaveMessage("");
  };

  const saveSelectedAsset = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!assetForm) return;

    setSavingAsset(true);
    setAssetSaveError("");
    setAssetSaveMessage("");
    try {
      const response = await fetch("/api/assets", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(assetForm),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(data.error || "Хөрөнгийн мэдээлэл шинэчилж чадсангүй.");
      }

      if (data.asset) {
        setAssets((current) =>
          current.map((asset) =>
            String(asset.id) === String(data.asset.id) ? data.asset : asset,
          ),
        );
        setSelectedAssetId(data.asset.id);
        setAssetForm(toAssetFormData(data.asset));
      }
      setAssetEditorOpen(false);
    } catch (error) {
      setAssetSaveError(
        error instanceof Error
          ? error.message
          : "Хөрөнгийн мэдээлэл шинэчилж чадсангүй.",
      );
    } finally {
      setSavingAsset(false);
    }
  };

  const distribution = useMemo(
    () =>
      ASSET_TYPE_OPTIONS.map((type, index) => ({
        type,
        label: ASSET_TYPE_METADATA[type]?.shortLabel ?? type,
        count: typeCounts.get(type) ?? 0,
        color: TYPE_COLORS[index % TYPE_COLORS.length],
      })).filter((item) => item.count > 0),
    [typeCounts],
  );

  const typeFilterOptions = useMemo(() => {
    const additionalTypes = Array.from(typeCounts.keys()).filter(
      (type) => !ASSET_TYPE_OPTIONS.includes(type),
    );

    return [ALL, ...ASSET_TYPE_OPTIONS, ...additionalTypes].map((type) => {
      const isAll = type === ALL;
      const label = isAll
        ? ALL
        : ASSET_TYPE_METADATA[type]?.shortLabel ||
          getLabel(ASSET_TYPE_LABELS, type) ||
          type;

      return {
        value: type,
        label,
        count: isAll ? assets.length : (typeCounts.get(type) ?? 0),
      };
    });
  }, [assets.length, typeCounts]);

  const donutGradient = useMemo(() => {
    if (stats.total === 0 || distribution.length === 0) return "#e2e8f0";
    let cursor = 0;
    const stops = distribution.map((item) => {
      const start = cursor;
      const span = (item.count / stats.total) * 100;
      cursor += span;
      return `${item.color} ${start}% ${cursor}%`;
    });
    return `conic-gradient(${stops.join(", ")})`;
  }, [distribution, stats.total]);

  if (!user) {
    return null;
  }

  const SelectedAssetIcon = getAssetIcon(selectedAsset?.asset_type);
  const enabledSecurityControlCount = assetForm
    ? SECURITY_CONTROL_ITEMS.filter(({ field }) => Boolean(assetForm[field]))
        .length
    : 0;

  return (
    <div className="app-page p-4 pb-8 sm:p-6 md:p-8">
      <div className="w-full">
        <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <h1 className="text-3xl font-bold sm:text-4xl">
              Хөрөнгийн бүртгэл
            </h1>
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            <div className="relative min-w-64 flex-1 lg:flex-none">
              <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Хөрөнгө хайх..."
                className="app-form-field h-10 w-full rounded-md border pl-9 pr-3 text-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
              />
            </div>
            <button
              type="button"
              onClick={() => setFiltersOpen((current) => !current)}
              className={`inline-flex h-10 items-center justify-center gap-2 rounded-md border px-3 text-sm font-medium shadow-sm ${
                filtersOpen || hasActiveFilters
                  ? "border-blue-200 bg-blue-50 text-blue-700"
                  : "border-border bg-background"
              }`}
            >
              <Filter className="size-4" />
              Шүүлтүүр
            </button>
            <ImportAssetsModal onImported={fetchAssets} />
            <AddAssetModal onAssetAdded={fetchAssets} />
          </div>
        </div>

        {filtersOpen && (
          <div className="mb-5 rounded-lg border border-border bg-card p-4 shadow-sm">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-5">
              <label className="text-sm font-medium">
                <span className="mb-1.5 block">Хөрөнгийн төрөл</span>
                <select
                  value={activeType}
                  onChange={(event) => setActiveType(event.target.value)}
                  className="app-form-field h-10 w-full rounded-md border px-3 text-sm"
                >
                  {typeFilterOptions.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label} ({option.count})
                    </option>
                  ))}
                </select>
              </label>
              <label className="text-sm font-medium">
                <span className="mb-1.5 block">Чухал байдлын түвшин</span>
                <select
                  value={criticalityFilter}
                  onChange={(event) => setCriticalityFilter(event.target.value)}
                  className="app-form-field h-10 w-full rounded-md border px-3 text-sm"
                >
                  <option value={ANY}>Бүх түвшин</option>
                  {CRITICALITY_LEVELS.map((level) => (
                    <option key={level} value={level}>
                      {getLabel(CRITICALITY_LABELS, level)}
                    </option>
                  ))}
                </select>
              </label>
              <label className="text-sm font-medium">
                <span className="mb-1.5 block">Өгөгдлийн ангилал</span>
                <select
                  value={dataFilter}
                  onChange={(event) => setDataFilter(event.target.value)}
                  className="app-form-field h-10 w-full rounded-md border px-3 text-sm"
                >
                  <option value={ANY}>Бүх ангилал</option>
                  {DATA_CLASSIFICATION_OPTIONS.map((classification) => (
                    <option key={classification} value={classification}>
                      {getLabel(DATA_CLASSIFICATION_LABELS, classification)}
                    </option>
                  ))}
                </select>
              </label>
              <label className="text-sm font-medium">
                <span className="mb-1.5 block">Төлөв</span>
                <select
                  value={statusFilter}
                  onChange={(event) => setStatusFilter(event.target.value)}
                  className="app-form-field h-10 w-full rounded-md border px-3 text-sm"
                >
                  <option value={ANY}>Бүх төлөв</option>
                  {STATUS_OPTIONS.map((status) => (
                    <option key={status} value={status}>
                      {getLabel(STATUS_LABELS, status)}
                    </option>
                  ))}
                </select>
              </label>
              <div className="flex items-end">
                <button
                  type="button"
                  onClick={clearFilters}
                  disabled={!hasActiveFilters}
                  className="inline-flex h-10 w-full items-center justify-center rounded-md border border-border px-3 text-sm font-medium text-muted-foreground transition hover:bg-accent hover:text-accent-foreground disabled:pointer-events-none disabled:opacity-40"
                >
                  Шүүлтүүр цэвэрлэх
                </button>
              </div>
            </div>
          </div>
        )}

        <div className="mb-5 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-6">
          {[
            {
              label: "Нийт хөрөнгө",
              value: stats.total,
              icon: Layers,
              surface: "border-blue-200 bg-blue-50 text-blue-700",
            },
            {
              label: "Чухал хөрөнгө",
              value: stats.critical,
              icon: ShieldAlert,
              surface: "border-red-200 bg-red-50 text-red-700",
            },
            {
              label: "Интернэтэд нээлттэй",
              value: stats.internetExposed,
              icon: Globe2,
              surface: "border-teal-200 bg-teal-50 text-teal-700",
            },
            {
              label: "Нууц өгөгдөлтэй хөрөнгө",
              value: stats.sensitive,
              icon: LockKeyhole,
              surface: "border-purple-200 bg-purple-50 text-purple-700",
            },
            {
              label: "Гуравдагч талын хамааралтай",
              value: stats.thirdParty,
              icon: Users,
              surface: "border-cyan-200 bg-cyan-50 text-cyan-700",
            },
            {
              label: "Өндөр эрсдэлтэй хөрөнгө",
              value: stats.highRisk,
              icon: AlertTriangle,
              surface: "border-orange-200 bg-orange-50 text-orange-700",
            },
          ].map(({ label, value, icon: Icon, surface }) => (
            <div
              key={label}
              className="rounded-lg border border-border bg-card p-4 shadow-sm"
            >
              <div className="mb-3 flex items-start justify-between gap-3">
                <span className="text-xs font-semibold text-muted-foreground">
                  {label}
                </span>
                <span className={`rounded-full border p-2 ${surface}`}>
                  <Icon className="size-4" />
                </span>
              </div>
              <div className="text-2xl font-bold">{value}</div>
              <div className="mt-3 flex h-6 items-end gap-1">
                {[2, 5, 3, 7, 4, 8, 6].map((height, index) => (
                  <span
                    key={index}
                    className="w-full rounded-sm bg-blue-500/20"
                    style={{ height: `${height * 3}px` }}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="space-y-5">
          <div className="flex min-w-0 flex-col gap-5">
            <div className="order-2 overflow-hidden rounded-lg border border-border bg-card shadow-sm">
              <div className="overflow-x-auto">
                <table className="w-full min-w-7xl table-fixed text-left text-sm">
                  <thead className="border-b border-border bg-muted/40 text-xs text-muted-foreground">
                    <tr>
                      <th className="w-16 px-3 py-3 text-center font-semibold">
                        Засах
                      </th>
                      <th className="w-80 px-3 py-3 font-semibold">
                        Хөрөнгийн нэр
                      </th>
                      <th className="w-36 px-3 py-3 font-semibold">Төрөл</th>
                      <th className="w-40 px-3 py-3 font-semibold">Ангилал</th>
                      <th className="w-32 px-3 py-3 font-semibold">Хэлтэс</th>
                      <th className="w-36 px-3 py-3 font-semibold">
                        Хариуцагч
                      </th>
                      <th className="w-32 px-3 py-3 font-semibold">Түвшин</th>
                      <th className="w-36 px-3 py-3 font-semibold">Өгөгдөл</th>
                      <th className="w-24 px-3 py-3 font-semibold">Интернэт</th>
                      <th className="w-20 px-3 py-3 font-semibold">Эрсдэл</th>
                      <th className="w-28 px-3 py-3 font-semibold">Төлөв</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {loading ? (
                      <tr>
                        <td
                          colSpan={11}
                          className="px-4 py-12 text-center text-muted-foreground"
                        >
                          Хөрөнгийн бүртгэл ачааллаж байна...
                        </td>
                      </tr>
                    ) : filteredAssets.length === 0 ? (
                      <tr>
                        <td
                          colSpan={11}
                          className="px-4 py-12 text-center text-muted-foreground"
                        >
                          Одоогийн нөхцөлд тохирох хөрөнгө олдсонгүй.
                        </td>
                      </tr>
                    ) : (
                      filteredAssets.map((asset) => {
                        const Icon = getAssetIcon(asset.asset_type);
                        const level = riskLevel(asset);
                        return (
                          <tr
                            key={asset.id}
                            className="bg-card transition hover:bg-muted/40"
                          >
                            <td className="px-3 py-3 text-center">
                              <button
                                type="button"
                                aria-label={`${asset.asset_name} хөрөнгийг засах`}
                                title="Хөрөнгө засах"
                                onClick={() => {
                                  setSelectedAssetId(asset.id ?? null);
                                  setAssetForm(toAssetFormData(asset));
                                  setAssetSaveError("");
                                  setAssetSaveMessage("");
                                  setAssetEditorOpen(true);
                                }}
                                className="inline-flex size-8 items-center justify-center rounded-md border border-transparent text-muted-foreground transition hover:border-border hover:bg-accent hover:text-foreground"
                              >
                                <Pencil className="size-4" />
                              </button>
                            </td>
                            <td className="px-3 py-3 align-top">
                              <div className="flex items-start gap-2">
                                <Icon className="mt-0.5 size-4 shrink-0 text-blue-600" />
                                <div className="min-w-0">
                                  <div className="whitespace-normal wrap-break-word font-semibold leading-5 text-blue-700">
                                    {asset.asset_name}
                                  </div>
                                  <div className="font-mono text-[11px] text-muted-foreground">
                                    {asset.asset_code ||
                                      asset.cmdb_ci_id ||
                                      "—"}
                                  </div>
                                </div>
                              </div>
                            </td>
                            <td className="px-3 py-3 text-xs">
                              {getAssetSubtype(asset)}
                            </td>
                            <td className="px-3 py-3 text-xs text-muted-foreground">
                              {ASSET_TYPE_METADATA[
                                getCanonicalAssetType(asset.asset_type)
                              ]?.shortLabel ||
                                getCanonicalAssetType(asset.asset_type) ||
                                "—"}
                            </td>
                            <td className="px-3 py-3 text-xs">
                              {asset.department || "—"}
                            </td>
                            <td className="px-3 py-3 text-xs">
                              {asset.business_owner ||
                                asset.technical_owner ||
                                "Хариуцагчгүй"}
                            </td>
                            <td className="px-3 py-3">
                              <span
                                className={`whitespace-nowrap rounded border px-2 py-1 text-[11px] font-semibold ${criticalityClass(
                                  asset.criticality,
                                )}`}
                                title={getLabel(
                                  CRITICALITY_LABELS,
                                  asset.criticality,
                                )}
                              >
                                {shortCriticalityLabel(asset.criticality)}
                              </span>
                            </td>
                            <td className="px-3 py-3">
                              {asset.data_classification ? (
                                <span
                                  className={`whitespace-nowrap rounded border px-2 py-1 text-[11px] font-semibold ${dataClass(
                                    asset.data_classification,
                                  )}`}
                                >
                                  {getLabel(
                                    DATA_CLASSIFICATION_LABELS,
                                    asset.data_classification,
                                  )}
                                </span>
                              ) : (
                                <span className="text-xs text-muted-foreground">
                                  —
                                </span>
                              )}
                            </td>
                            <td className="px-3 py-3 text-xs">
                              {asset.internet_exposed ? "Тийм" : "Үгүй"}
                            </td>
                            <td className="px-3 py-3">
                              <span
                                className={`rounded border px-2 py-1 text-[11px] font-semibold ${riskClass(
                                  level,
                                )}`}
                              >
                                {riskSignalCount(asset)}
                              </span>
                            </td>
                            <td className="px-3 py-3">
                              <span
                                className={`whitespace-nowrap rounded border px-2 py-1 text-[11px] font-semibold ${statusClass(
                                  asset.status,
                                )}`}
                              >
                                {getLabel(STATUS_LABELS, asset.status) ||
                                  asset.status ||
                                  "—"}
                              </span>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>

              <div className="flex items-center justify-between gap-3 border-t border-border px-4 py-3 text-xs text-muted-foreground">
                <span>
                  {assets.length} хөрөнгөөс {filteredAssets.length}-г харуулж
                  байна
                </span>
                <span>Нэг хуудсанд: 25</span>
              </div>
            </div>

            {assetEditorOpen && assetForm && selectedAsset && (
              <div className="fixed inset-0 z-10000 flex items-center justify-center bg-black/70 px-3 py-4 sm:px-6">
                <button
                  type="button"
                  aria-label="Хөрөнгийн засварлах цонх хаах"
                  className="absolute inset-0 cursor-default"
                  onClick={() => setAssetEditorOpen(false)}
                />
                <form
                  onSubmit={saveSelectedAsset}
                  role="dialog"
                  aria-modal="true"
                  aria-labelledby="asset-editor-title"
                  className="app-card-surface relative flex max-h-[calc(100vh-2rem)] w-full max-w-6xl flex-col overflow-hidden rounded-lg border border-border shadow-2xl"
                >
                  <div className="border-b border-border bg-card/95 px-4 py-4 backdrop-blur sm:px-5">
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                      <div className="flex min-w-0 items-start gap-3">
                        <span className="flex size-11 shrink-0 items-center justify-center rounded-md bg-blue-50 text-blue-700 dark:bg-blue-950/40 dark:text-blue-300">
                          <SelectedAssetIcon className="size-5" />
                        </span>
                        <div className="min-w-0">
                          <h2
                            id="asset-editor-title"
                            className="text-xl font-bold leading-7"
                          >
                            Хөрөнгийн мэдээлэл засах
                          </h2>
                          <p className="mt-1 truncate text-sm text-muted-foreground">
                            {assetForm.asset_name || "Нэргүй хөрөнгө"}
                            {assetForm.asset_code
                              ? ` · ${assetForm.asset_code}`
                              : ""}
                          </p>
                        </div>
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`rounded border px-2.5 py-1 text-xs font-semibold ${criticalityClass(
                            assetForm.criticality,
                          )}`}
                          title={getLabel(
                            CRITICALITY_LABELS,
                            assetForm.criticality,
                          )}
                        >
                          {shortCriticalityLabel(assetForm.criticality)}
                        </span>
                        <span
                          className={`rounded border px-2.5 py-1 text-xs font-semibold ${riskClass(
                            riskLevel(selectedAsset),
                          )}`}
                        >
                          {getLabel(
                            RISK_LEVEL_LABELS,
                            riskLevel(selectedAsset),
                          )}{" "}
                          эрсдэл
                        </span>
                        <button
                          type="button"
                          onClick={() => setAssetEditorOpen(false)}
                          aria-label="Хөрөнгийн засварлах цонх хаах"
                          className="inline-flex size-9 items-center justify-center rounded-md border border-border bg-background text-muted-foreground transition hover:bg-accent hover:text-foreground"
                        >
                          <X className="size-4" />
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className="min-h-0 flex-1 overflow-y-auto px-4 py-5 sm:px-5">
                    <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_290px] xl:grid-cols-[minmax(0,1fr)_320px]">
                      <div className="space-y-5">
                        <section className={EDIT_SECTION_CLASS}>
                          <div className="mb-4 flex items-center justify-between gap-3">
                            <h3 className={EDIT_SECTION_TITLE_CLASS}>
                              <FileText className="size-4 text-blue-600" />
                              Үндсэн мэдээлэл
                            </h3>
                          </div>
                          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                            <label className="text-sm font-medium md:col-span-2">
                              <span className="mb-1.5 block">
                                Хөрөнгийн нэр{" "}
                                <span className="text-red-500">*</span>
                              </span>
                              <input
                                value={assetForm.asset_name}
                                onChange={(event) =>
                                  updateAssetFormField(
                                    "asset_name",
                                    event.target.value,
                                  )
                                }
                                required
                                className={FIELD_CLASS}
                              />
                            </label>
                            <label className="text-sm font-medium">
                              <span className="mb-1.5 block">
                                Хөрөнгийн код
                              </span>
                              <input
                                value={assetForm.asset_code}
                                onChange={(event) =>
                                  updateAssetFormField(
                                    "asset_code",
                                    event.target.value,
                                  )
                                }
                                className={FIELD_CLASS}
                              />
                            </label>
                            <label className="text-sm font-medium">
                              <span className="mb-1.5 block">Төлөв</span>
                              <select
                                value={assetForm.status}
                                onChange={(event) =>
                                  updateAssetFormField(
                                    "status",
                                    event.target.value,
                                  )
                                }
                                className={FIELD_CLASS}
                              >
                                {STATUS_OPTIONS.map((status) => (
                                  <option key={status} value={status}>
                                    {getLabel(STATUS_LABELS, status)}
                                  </option>
                                ))}
                              </select>
                            </label>
                            <label className="text-sm font-medium">
                              <span className="mb-1.5 block">
                                Хөрөнгийн ангилал{" "}
                                <span className="text-red-500">*</span>
                              </span>
                              <select
                                value={assetForm.asset_type}
                                onChange={(event) =>
                                  updateAssetFormField(
                                    "asset_type",
                                    event.target.value,
                                  )
                                }
                                required
                                className={FIELD_CLASS}
                              >
                                <option value="">Ангилал сонгох...</option>
                                {ASSET_TYPE_OPTIONS.map((type) => (
                                  <option key={type} value={type}>
                                    {ASSET_TYPE_METADATA[type]?.label ??
                                      getLabel(ASSET_TYPE_LABELS, type)}
                                  </option>
                                ))}
                              </select>
                            </label>
                            <label className="text-sm font-medium">
                              <span className="mb-1.5 block">
                                Чухал байдлын түвшин{" "}
                                <span className="text-red-500">*</span>
                              </span>
                              <select
                                value={assetForm.criticality}
                                onChange={(event) =>
                                  updateAssetFormField(
                                    "criticality",
                                    event.target.value,
                                  )
                                }
                                required
                                className={FIELD_CLASS}
                              >
                                <option value="">Түвшин сонгох...</option>
                                {CRITICALITY_LEVELS.map((level) => (
                                  <option key={level} value={level}>
                                    {getLabel(CRITICALITY_LABELS, level)}
                                  </option>
                                ))}
                              </select>
                            </label>
                            <label className="text-sm font-medium">
                              <span className="mb-1.5 block">
                                Өгөгдлийн ангилал
                              </span>
                              <select
                                value={assetForm.data_classification}
                                onChange={(event) =>
                                  updateAssetFormField(
                                    "data_classification",
                                    event.target.value,
                                  )
                                }
                                className={FIELD_CLASS}
                              >
                                <option value="">Ангилал сонгох...</option>
                                {DATA_CLASSIFICATION_OPTIONS.map(
                                  (classification) => (
                                    <option
                                      key={classification}
                                      value={classification}
                                    >
                                      {getLabel(
                                        DATA_CLASSIFICATION_LABELS,
                                        classification,
                                      )}
                                    </option>
                                  ),
                                )}
                              </select>
                            </label>
                            <label className="text-sm font-medium">
                              <span className="mb-1.5 block">Байршуулалт</span>
                              <select
                                value={assetForm.hosting}
                                onChange={(event) =>
                                  updateAssetFormField(
                                    "hosting",
                                    event.target.value,
                                  )
                                }
                                className={FIELD_CLASS}
                              >
                                <option value="">Байршуулалт сонгох...</option>
                                {getHostingOptions(assetForm.asset_type).map(
                                  (hosting) => (
                                    <option key={hosting} value={hosting}>
                                      {getLabel(HOSTING_LABELS, hosting)}
                                    </option>
                                  ),
                                )}
                              </select>
                            </label>
                          </div>
                        </section>

                        <section className={EDIT_SECTION_CLASS}>
                          <div className="mb-4 flex items-center justify-between gap-3">
                            <h3 className={EDIT_SECTION_TITLE_CLASS}>
                              <LockKeyhole className="size-4 text-blue-600" />
                              Хандалт ба эрсдэлийн хүчин зүйлс
                            </h3>
                          </div>
                          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                            <label className="text-sm font-medium">
                              <span className="mb-1.5 block">
                                Хандалтын түвшин
                              </span>
                              <select
                                value={assetForm.access_level}
                                onChange={(event) =>
                                  updateAssetFormField(
                                    "access_level",
                                    event.target.value,
                                  )
                                }
                                className={FIELD_CLASS}
                              >
                                <option value="">Хандалт сонгох...</option>
                                {ACCESS_LEVEL_OPTIONS.map((access) => (
                                  <option key={access} value={access}>
                                    {getLabel(ACCESS_LEVEL_LABELS, access)}
                                  </option>
                                ))}
                              </select>
                            </label>
                            <label className="text-sm font-medium">
                              <span className="mb-1.5 block">
                                Танин баталгаажуулалт
                              </span>
                              <select
                                value={assetForm.authentication_method}
                                onChange={(event) =>
                                  updateAssetFormField(
                                    "authentication_method",
                                    event.target.value,
                                  )
                                }
                                className={FIELD_CLASS}
                              >
                                <option value="">
                                  Танин баталгаажуулалт сонгох...
                                </option>
                                {AUTHENTICATION_METHOD_OPTIONS.map((method) => (
                                  <option key={method} value={method}>
                                    {getLabel(
                                      AUTHENTICATION_METHOD_LABELS,
                                      method,
                                    )}
                                  </option>
                                ))}
                              </select>
                            </label>
                            <label className="text-sm font-medium">
                              <span className="mb-1.5 block">RTO цаг</span>
                              <input
                                value={assetForm.rto_hours}
                                onChange={(event) =>
                                  updateAssetFormField(
                                    "rto_hours",
                                    event.target.value,
                                  )
                                }
                                type="number"
                                min="0"
                                step="0.25"
                                className={FIELD_CLASS}
                              />
                            </label>
                            <label className="text-sm font-medium">
                              <span className="mb-1.5 block">RPO цаг</span>
                              <input
                                value={assetForm.rpo_hours}
                                onChange={(event) =>
                                  updateAssetFormField(
                                    "rpo_hours",
                                    event.target.value,
                                  )
                                }
                                type="number"
                                min="0"
                                step="0.25"
                                className={FIELD_CLASS}
                              />
                            </label>
                          </div>
                        </section>

                        <section className={EDIT_SECTION_CLASS}>
                          <div className="mb-4 flex items-center justify-between gap-3">
                            <h3 className={EDIT_SECTION_TITLE_CLASS}>
                              <Building2 className="size-4 text-blue-600" />
                              Хариуцагч ба холбоос
                            </h3>
                          </div>
                          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                            <label className="text-sm font-medium">
                              <span className="mb-1.5 block">
                                Бизнесийн хариуцагч
                              </span>
                              <input
                                value={assetForm.business_owner}
                                onChange={(event) =>
                                  updateAssetFormField(
                                    "business_owner",
                                    event.target.value,
                                  )
                                }
                                className={FIELD_CLASS}
                              />
                            </label>
                            <label className="text-sm font-medium">
                              <span className="mb-1.5 block">
                                Техникийн хариуцагч
                              </span>
                              <input
                                value={assetForm.technical_owner}
                                onChange={(event) =>
                                  updateAssetFormField(
                                    "technical_owner",
                                    event.target.value,
                                  )
                                }
                                className={FIELD_CLASS}
                              />
                            </label>
                            <label className="text-sm font-medium">
                              <span className="mb-1.5 block">Хэлтэс</span>
                              <input
                                value={assetForm.department}
                                onChange={(event) =>
                                  updateAssetFormField(
                                    "department",
                                    event.target.value,
                                  )
                                }
                                className={FIELD_CLASS}
                              />
                            </label>
                            <label className="text-sm font-medium">
                              <span className="mb-1.5 block">CMDB CI ID</span>
                              <input
                                value={assetForm.cmdb_ci_id}
                                onChange={(event) =>
                                  updateAssetFormField(
                                    "cmdb_ci_id",
                                    event.target.value,
                                  )
                                }
                                className={FIELD_CLASS}
                              />
                            </label>
                            <label className="text-sm font-medium md:col-span-2">
                              <span className="mb-1.5 block">
                                Гол хэрэглэгчид / харилцагчид
                              </span>
                              <input
                                value={assetForm.key_users_customers}
                                onChange={(event) =>
                                  updateAssetFormField(
                                    "key_users_customers",
                                    event.target.value,
                                  )
                                }
                                className={FIELD_CLASS}
                              />
                            </label>
                          </div>
                        </section>

                        {selectedAssetMetadata && (
                          <section className={EDIT_SECTION_CLASS}>
                            <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                              <div>
                                <h3 className={EDIT_SECTION_TITLE_CLASS}>
                                  <Layers className="size-4 text-blue-600" />
                                  {selectedAssetMetadata.label}
                                </h3>
                                <p className="mt-1 text-xs text-muted-foreground">
                                  {selectedAssetMetadata.description}
                                </p>
                              </div>
                            </div>
                            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                              {selectedDetailFields.map((field) => {
                                const value =
                                  assetForm.asset_details[field.name] ?? "";
                                const id = `edit-${field.name}`;
                                if (field.input === "textarea") {
                                  return (
                                    <label
                                      key={field.name}
                                      className="text-sm font-medium md:col-span-2"
                                    >
                                      <span className="mb-1.5 block">
                                        {field.label}
                                      </span>
                                      <textarea
                                        id={id}
                                        value={value}
                                        onChange={(event) =>
                                          updateAssetDetailField(
                                            field.name,
                                            event.target.value,
                                          )
                                        }
                                        placeholder={field.placeholder}
                                        className={TEXTAREA_CLASS}
                                      />
                                    </label>
                                  );
                                }

                                if (field.input === "select") {
                                  return (
                                    <label
                                      key={field.name}
                                      className="text-sm font-medium"
                                    >
                                      <span className="mb-1.5 block">
                                        {field.label}
                                      </span>
                                      <select
                                        id={id}
                                        value={value}
                                        onChange={(event) =>
                                          updateAssetDetailField(
                                            field.name,
                                            event.target.value,
                                          )
                                        }
                                        className={FIELD_CLASS}
                                      >
                                        <option value="">Сонгоно уу...</option>
                                        {(field.options ?? []).map((option) => (
                                          <option key={option} value={option}>
                                            {getLabel(
                                              ASSET_DETAIL_OPTION_LABELS,
                                              option,
                                            )}
                                          </option>
                                        ))}
                                      </select>
                                    </label>
                                  );
                                }

                                return (
                                  <label
                                    key={field.name}
                                    className="text-sm font-medium"
                                  >
                                    <span className="mb-1.5 block">
                                      {field.label}
                                    </span>
                                    <input
                                      id={id}
                                      value={value}
                                      onChange={(event) =>
                                        updateAssetDetailField(
                                          field.name,
                                          event.target.value,
                                        )
                                      }
                                      placeholder={field.placeholder}
                                      className={FIELD_CLASS}
                                    />
                                  </label>
                                );
                              })}
                            </div>
                          </section>
                        )}

                        <section className={EDIT_SECTION_CLASS}>
                          <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                            <h3 className={EDIT_SECTION_TITLE_CLASS}>
                              <ShieldAlert className="size-4 text-blue-600" />
                              Аюулгүй байдлын хамрах хүрээ
                            </h3>
                            <span className="text-xs font-medium text-muted-foreground">
                              {enabledSecurityControlCount}/
                              {SECURITY_CONTROL_ITEMS.length}
                            </span>
                          </div>
                          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                            {SECURITY_CONTROL_ITEMS.map(
                              ({ field, label, risk }) => {
                                const enabled = Boolean(assetForm[field]);
                                return (
                                  <button
                                    key={field}
                                    type="button"
                                    onClick={() =>
                                      toggleAssetSecurityControl(field)
                                    }
                                    className={`flex min-h-12 cursor-pointer items-center justify-between gap-3 rounded-md border px-3 py-2 text-sm transition ${
                                      enabled
                                        ? risk
                                          ? "border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-900/70 dark:bg-amber-950/30 dark:text-amber-200"
                                          : "border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-900/70 dark:bg-emerald-950/30 dark:text-emerald-200"
                                        : "border-border bg-card hover:bg-accent/50"
                                    }`}
                                  >
                                    <span className="min-w-0 font-medium">
                                      {label}
                                    </span>
                                    <span
                                      className={`relative h-5 w-9 shrink-0 rounded-full transition ${
                                        enabled
                                          ? risk
                                            ? "bg-amber-500"
                                            : "bg-emerald-500"
                                          : "bg-muted-foreground/30"
                                      }`}
                                    >
                                      <span
                                        className={`absolute top-0.5 size-4 rounded-full bg-white shadow transition ${
                                          enabled ? "left-4" : "left-0.5"
                                        }`}
                                      />
                                    </span>
                                  </button>
                                );
                              },
                            )}
                          </div>
                        </section>

                        <section className={EDIT_SECTION_CLASS}>
                          <label className="block text-sm font-medium">
                            <span className="mb-1.5 flex items-center gap-2">
                              <FileText className="size-4 text-blue-600" />
                              Тэмдэглэл
                            </span>
                            <textarea
                              value={assetForm.notes}
                              onChange={(event) =>
                                updateAssetFormField(
                                  "notes",
                                  event.target.value,
                                )
                              }
                              className={TEXTAREA_CLASS}
                            />
                          </label>
                        </section>
                      </div>

                      <aside className="space-y-3 lg:sticky lg:top-0 lg:self-start">
                        <div className="rounded-lg border border-border bg-background/70 p-4 shadow-sm">
                          <div className="flex items-start gap-3">
                            <span className="flex size-10 shrink-0 items-center justify-center rounded-md bg-blue-50 text-blue-700 dark:bg-blue-950/40 dark:text-blue-300">
                              <SelectedAssetIcon className="size-5" />
                            </span>
                            <div className="min-w-0">
                              <p className="truncate text-sm font-semibold">
                                {assetForm.asset_name || "Нэргүй хөрөнгө"}
                              </p>
                              <p className="mt-1 text-xs text-muted-foreground">
                                {getLabel(
                                  ASSET_TYPE_LABELS,
                                  assetForm.asset_type,
                                ) ||
                                  selectedAssetMetadata?.shortLabel ||
                                  "Ангилагдаагүй"}
                              </p>
                            </div>
                          </div>

                          <div className="mt-4 grid grid-cols-2 gap-2">
                            <div className={EDIT_SUMMARY_ITEM_CLASS}>
                              <span className="block text-[11px] font-medium uppercase text-muted-foreground">
                                Код
                              </span>
                              <span className="mt-1 block truncate text-sm font-semibold">
                                {assetForm.asset_code || "—"}
                              </span>
                            </div>
                            <div className={EDIT_SUMMARY_ITEM_CLASS}>
                              <span className="block text-[11px] font-medium uppercase text-muted-foreground">
                                Төлөв
                              </span>
                              <span className="mt-1 block truncate text-sm font-semibold">
                                {getLabel(STATUS_LABELS, assetForm.status) ||
                                  assetForm.status ||
                                  "—"}
                              </span>
                            </div>
                            <div className={EDIT_SUMMARY_ITEM_CLASS}>
                              <span className="block text-[11px] font-medium uppercase text-muted-foreground">
                                RTO
                              </span>
                              <span className="mt-1 block truncate text-sm font-semibold">
                                {assetForm.rto_hours || "—"}
                              </span>
                            </div>
                            <div className={EDIT_SUMMARY_ITEM_CLASS}>
                              <span className="block text-[11px] font-medium uppercase text-muted-foreground">
                                RPO
                              </span>
                              <span className="mt-1 block truncate text-sm font-semibold">
                                {assetForm.rpo_hours || "—"}
                              </span>
                            </div>
                          </div>

                          <div className="mt-4 rounded-md border border-border bg-card px-3 py-3">
                            <div className="flex items-center justify-between gap-3 text-xs font-medium">
                              <span className="text-muted-foreground">
                                Хяналтын бөглөлт
                              </span>
                              <span>
                                {enabledSecurityControlCount}/
                                {SECURITY_CONTROL_ITEMS.length}
                              </span>
                            </div>
                            <div className="mt-2 h-2 overflow-hidden rounded-full bg-muted">
                              <div
                                className="h-full rounded-full bg-blue-600 transition-all"
                                style={{
                                  width: `${
                                    (enabledSecurityControlCount /
                                      SECURITY_CONTROL_ITEMS.length) *
                                    100
                                  }%`,
                                }}
                              />
                            </div>
                          </div>

                          <div className="mt-4 space-y-2 text-sm">
                            <div className="flex items-start justify-between gap-3">
                              <span className="text-muted-foreground">
                                Өгөгдөл
                              </span>
                              <span className="text-right font-medium">
                                {getLabel(
                                  DATA_CLASSIFICATION_LABELS,
                                  assetForm.data_classification,
                                ) ||
                                  assetForm.data_classification ||
                                  "—"}
                              </span>
                            </div>
                            <div className="flex items-start justify-between gap-3">
                              <span className="text-muted-foreground">
                                Байршуулалт
                              </span>
                              <span className="text-right font-medium">
                                {getLabel(HOSTING_LABELS, assetForm.hosting) ||
                                  assetForm.hosting ||
                                  "—"}
                              </span>
                            </div>
                            <div className="flex items-start justify-between gap-3">
                              <span className="text-muted-foreground">
                                Хариуцагч
                              </span>
                              <span className="text-right font-medium">
                                {assetForm.business_owner || "—"}
                              </span>
                            </div>
                          </div>
                        </div>

                        <div className="rounded-lg border border-border bg-background/70 p-4 text-sm shadow-sm">
                          <div className="mb-3 flex items-center gap-2 font-semibold">
                            <AlertTriangle className="size-4 text-amber-600" />
                            Эрсдэлийн төлөв
                          </div>
                          <div className="flex flex-wrap gap-2">
                            <span
                              className={`rounded border px-2 py-1 text-xs font-semibold ${criticalityClass(
                                assetForm.criticality,
                              )}`}
                            >
                              {shortCriticalityLabel(assetForm.criticality)}
                            </span>
                            <span
                              className={`rounded border px-2 py-1 text-xs font-semibold ${riskClass(
                                riskLevel(selectedAsset),
                              )}`}
                            >
                              {getLabel(
                                RISK_LEVEL_LABELS,
                                riskLevel(selectedAsset),
                              )}{" "}
                              эрсдэл
                            </span>
                          </div>
                        </div>
                      </aside>
                    </div>
                  </div>

                  <div className="border-t border-border bg-card/95 px-4 py-4 backdrop-blur sm:px-5">
                    <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                      <div className="min-h-9 flex-1">
                        {assetSaveError && (
                          <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-900/70 dark:bg-red-950/30 dark:text-red-300">
                            {assetSaveError}
                          </div>
                        )}
                        {assetSaveMessage && (
                          <div className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-700 dark:border-emerald-900/70 dark:bg-emerald-950/30 dark:text-emerald-300">
                            {assetSaveMessage}
                          </div>
                        )}
                      </div>
                      <div className="flex flex-wrap justify-end gap-2">
                        <button
                          type="button"
                          onClick={() => setAssetEditorOpen(false)}
                          className="inline-flex h-10 items-center justify-center rounded-md border border-border bg-background px-4 text-sm font-medium transition hover:bg-accent hover:text-accent-foreground"
                        >
                          Болих
                        </button>
                        <button
                          type="button"
                          onClick={resetSelectedAssetForm}
                          className="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-border bg-background px-4 text-sm font-medium transition hover:bg-accent hover:text-accent-foreground"
                        >
                          <RotateCcw className="size-4" />
                          Дахин тохируулах
                        </button>
                        <button
                          type="submit"
                          disabled={savingAsset}
                          className="inline-flex h-10 items-center justify-center gap-2 rounded-md bg-blue-600 px-4 text-sm font-medium text-white transition hover:bg-blue-700 disabled:pointer-events-none disabled:opacity-60"
                        >
                          <Save className="size-4" />
                          {savingAsset
                            ? "Хадгалж байна..."
                            : "Өөрчлөлт хадгалах"}
                        </button>
                      </div>
                    </div>
                  </div>
                </form>
              </div>
            )}

            <div className="order-3 rounded-lg border border-border bg-card p-4 shadow-sm">
              <div className="mb-4 flex items-center justify-between gap-3">
                <h2 className="text-sm font-semibold">Хөрөнгийн тархалт</h2>
                <span className="rounded-md border border-border px-2 py-1 text-xs text-muted-foreground">
                  Ангиллаар
                </span>
              </div>
              <div className="grid gap-5 md:grid-cols-[180px_minmax(0,1fr)]">
                <div className="flex items-center justify-center">
                  <div
                    className="grid size-36 place-items-center rounded-full"
                    style={{ background: donutGradient }}
                  >
                    <div className="grid size-24 place-items-center rounded-full bg-card text-center">
                      <span>
                        <span className="block text-2xl font-bold">
                          {stats.total}
                        </span>
                        <span className="text-xs text-muted-foreground">
                          Нийт
                        </span>
                      </span>
                    </div>
                  </div>
                </div>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  {distribution.length === 0 ? (
                    <p className="text-sm text-muted-foreground">
                      Тархалтын мэдээлэл хараахан алга.
                    </p>
                  ) : (
                    distribution.map((item) => (
                      <div
                        key={item.type}
                        className="flex items-center justify-between gap-3 rounded-md border border-border bg-background px-3 py-2 text-sm"
                      >
                        <span className="flex min-w-0 items-center gap-2">
                          <span
                            className="size-3 shrink-0 rounded-sm"
                            style={{ background: item.color }}
                          />
                          <span className="truncate">{item.label}</span>
                        </span>
                        <span className="font-semibold">
                          {item.count}{" "}
                          <span className="text-xs text-muted-foreground">
                            ({Math.round((item.count / stats.total) * 100)}%)
                          </span>
                        </span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
