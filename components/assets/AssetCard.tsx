"use client";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Cloud,
  Database,
  Globe2,
  HardDrive,
  KeyRound,
  LockKeyhole,
  MonitorSmartphone,
  Network,
  Pencil,
  Server,
  ShieldAlert,
  Trash2,
  XCircle,
  type LucideIcon,
} from "lucide-react";
import {
  memo,
  useEffect,
  useState,
  type ChangeEvent,
  type FormEvent,
} from "react";
import {
  ACCESS_LEVEL_LABELS,
  ACCESS_LEVEL_OPTIONS,
  ASSET_TYPE_LABELS,
  ASSET_TYPE_OPTIONS,
  AUTHENTICATION_METHOD_LABELS,
  AUTHENTICATION_METHOD_OPTIONS,
  COUNTRY_OPTIONS,
  COUNTRY_REGION_MAP,
  CRITICALITY_LABELS,
  CRITICALITY_LEVELS,
  DATA_CLASSIFICATION_LABELS,
  DATA_CLASSIFICATION_OPTIONS,
  getHostingOptions,
  getLabel,
  HOSTING_LABELS,
  NATIVE_SELECT_CLASS,
  STATUS_LABELS,
  STATUS_OPTIONS,
} from "./asset-constants";

interface CriticalBusinessProcess {
  id: number;
  process_code?: string | null;
  process_name: string;
  criticality?: string | null;
  status?: string | null;
  dependency_type?: string | null;
  risk_count?: number;
  highest_risk_score?: number | string | null;
  highest_risk_level?: string | null;
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
  country?: string;
  region?: string;
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
  status?: string;
  created_at?: string;
  updated_at?: string;
}

interface AssetCardProps {
  asset: Asset;
  getCriticalityColor: (criticality: string) => string;
  getStatusColor: (status: string) => string;
  onAssetUpdated?: (asset: Asset) => void;
  onAssetRemoved?: (assetId: string | number) => void;
}

const RISK_LEVEL_COLORS: Record<string, string> = {
  Critical: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-400",
  High: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-400",
  Medium:
    "bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-400",
  Low: "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-400",
};

const EDITABLE_FIELD_CLASS = "app-form-field mt-1 h-10";
const EDIT_PANEL_CLASS = "app-form-panel rounded-lg border p-3";
const EDIT_CHOICE_INPUT_CLASS =
  "app-choice-input size-4 rounded accent-blue-600";

const formatBusinessProcessLabel = (process: CriticalBusinessProcess) =>
  process.process_name;

const toScoreNumber = (value?: number | string | null) => {
  const score = Number(value ?? 0);
  return Number.isFinite(score) ? score : 0;
};

const getAssetFormData = (asset: Asset) => ({
  id: asset.id ?? "",
  asset_type_id: asset.asset_type_id?.toString() ?? "",
  asset_type: asset.asset_type ?? "",
  owner_id: asset.owner_id?.toString() ?? "",
  asset_name: asset.asset_name ?? "",
  asset_code: asset.asset_code ?? "",
  business_owner: asset.business_owner ?? "",
  technical_owner: asset.technical_owner ?? "",
  department: asset.department ?? "",
  data_classification: asset.data_classification ?? "",
  access_level:
    asset.access_level ??
    (asset.internet_exposed ? "Public web access" : "Internal only"),
  authentication_method: asset.authentication_method ?? "",
  supports_critical_service: Boolean(asset.supports_critical_service),
  business_process_ids:
    asset.business_process_ids ??
    asset.critical_business_processes?.map((process) => process.id) ??
    [],
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
  status: asset.status ?? "Active",
});

const formatHours = (value?: number | string) => {
  if (value === undefined || value === null || value === "") return null;
  const text = String(value).trim();
  if (!text) return null;
  return text.toLowerCase().endsWith("h") ? text : `${text}ц`;
};

const getCriticalityVisuals = (criticality: string) => {
  if (criticality.includes("Tier 0"))
    return {
      bar: "bg-red-500",
      iconShell:
        "border-red-200 bg-red-50 text-red-700 dark:border-red-900/70 dark:bg-red-950/40 dark:text-red-300",
      signal: "bg-red-500",
    };
  if (criticality.includes("Tier 1"))
    return {
      bar: "bg-orange-500",
      iconShell:
        "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-900/70 dark:bg-orange-950/40 dark:text-orange-300",
      signal: "bg-orange-500",
    };
  if (criticality.includes("Tier 2"))
    return {
      bar: "bg-amber-400",
      iconShell:
        "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900/70 dark:bg-amber-950/40 dark:text-amber-300",
      signal: "bg-amber-400",
    };
  return {
    bar: "bg-emerald-500",
    iconShell:
      "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900/70 dark:bg-emerald-950/40 dark:text-emerald-300",
    signal: "bg-emerald-500",
  };
};

const getAssetTypeIcon = (assetType?: string): LucideIcon => {
  const t = assetType?.toLowerCase() ?? "";
  if (t.includes("database")) return Database;
  if (/(saas|cloud|azure|aws|gcp)/.test(t)) return Cloud;
  if (/(endpoint|fleet|workstation|device)/.test(t)) return MonitorSmartphone;
  if (/(network|vpn|load balancer)/.test(t)) return Network;
  if (/(storage|backup|file)/.test(t)) return HardDrive;
  if (/(identity|provider|mfa)/.test(t)) return KeyRound;
  return Server;
};

const AssetCard = memo(
  ({
    asset,
    getCriticalityColor,
    getStatusColor,
    onAssetUpdated,
    onAssetRemoved,
  }: AssetCardProps) => {
    const [editOpen, setEditOpen] = useState(false);
    const [saving, setSaving] = useState(false);
    const [removing, setRemoving] = useState(false);
    const [saveError, setSaveError] = useState("");
    const [formData, setFormData] = useState(() => getAssetFormData(asset));
    const [businessProcesses, setBusinessProcesses] = useState<
      CriticalBusinessProcess[]
    >([]);
    const [businessProcessesLoading, setBusinessProcessesLoading] =
      useState(false);
    const [businessProcessesFetched, setBusinessProcessesFetched] =
      useState(false);
    useEffect(() => {
      if (!editOpen) setFormData(getAssetFormData(asset));
    }, [asset, editOpen]);

    useEffect(() => {
      if (!editOpen || businessProcessesFetched) return;

      setBusinessProcessesLoading(true);
      fetch("/api/business-processes")
        .then((response) => {
          if (!response.ok)
            throw new Error("Business process list fetch failed");
          return response.json();
        })
        .then((data) => {
          const processes = Array.isArray(data.processes)
            ? data.processes.filter(
                (process: CriticalBusinessProcess) =>
                  process.status !== "Inactive" &&
                  String(process.criticality ?? "Critical").toLowerCase() ===
                    "critical",
              )
            : [];
          setBusinessProcesses(processes);
          setBusinessProcessesFetched(true);
        })
        .catch((error) => {
          console.error(
            "Business process жагсаалт татах үед алдаа гарлаа:",
            error,
          );
          setBusinessProcesses([]);
        })
        .finally(() => setBusinessProcessesLoading(false));
    }, [editOpen, businessProcessesFetched]);

    const handleEditOpenChange = (open: boolean) => {
      setEditOpen(open);
      setSaveError("");
      if (open) {
        setFormData(getAssetFormData(asset));
      }
    };

    const handleRemove = async () => {
      if (asset.id === undefined || asset.id === null || asset.id === "") {
        setSaveError("Устгах хөрөнгийн дугаар олдсонгүй.");
        return;
      }
      if (
        !window.confirm(
          "Энэ хөрөнгийг устгахдаа итгэлтэй байна уу? Холбоотой бүртгэлүүд устаж болзошгүй.",
        )
      )
        return;

      setRemoving(true);
      setSaveError("");
      try {
        const response = await fetch(
          `/api/assets?id=${encodeURIComponent(String(asset.id))}`,
          { method: "DELETE" },
        );
        const data = await response.json().catch(() => ({}));
        if (!response.ok)
          throw new Error(data.error || "Хөрөнгө устгаж чадсангүй.");
        onAssetRemoved?.(data.deletedId ?? asset.id);
        setEditOpen(false);
      } catch (error) {
        setSaveError(
          error instanceof Error ? error.message : "Хөрөнгө устгаж чадсангүй.",
        );
      } finally {
        setRemoving(false);
      }
    };

    const handleInputChange = (
      e: ChangeEvent<
        HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement
      >,
    ) => {
      const { name, value } = e.target;
      setFormData((prev) => {
        const isCriticalService =
          name === "supports_critical_service" ? value === "true" : null;

        return {
          ...prev,
          [name]: isCriticalService === null ? value : isCriticalService,
          ...(isCriticalService === false ? { business_process_ids: [] } : {}),
          ...(name === "country"
            ? { region: COUNTRY_REGION_MAP[value] ?? "" }
            : {}),
          ...(name === "asset_type"
            ? {
                hosting: getHostingOptions(value).includes(prev.hosting)
                  ? prev.hosting
                  : "",
              }
            : {}),
          ...(name === "access_level"
            ? {
                internet_exposed: [
                  "Public web access",
                  "Public API exposed",
                ].includes(value),
              }
            : {}),
          ...(name === "authentication_method"
            ? {
                mfa_enabled: [
                  "Password + MFA",
                  "SSO",
                  "Active Directory",
                ].includes(value),
              }
            : {}),
        };
      });
      setSaveError("");
    };

    const handleCheckboxChange = (e: ChangeEvent<HTMLInputElement>) => {
      const { name, checked } = e.target;
      setFormData((prev) => ({ ...prev, [name]: checked }));
      setSaveError("");
    };

    const handleBusinessProcessToggle = (processId: number) => {
      setFormData((prev) => {
        const current = prev.business_process_ids;
        const next = current.includes(processId)
          ? current.filter((id) => id !== processId)
          : [...current, processId];

        return {
          ...prev,
          supports_critical_service: true,
          business_process_ids: next,
        };
      });
      setSaveError("");
    };

    const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
      e.preventDefault();
      setSaving(true);
      setSaveError("");
      try {
        const response = await fetch("/api/assets", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(formData),
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok)
          throw new Error(
            data.error || "Хөрөнгийн мэдээллийг шинэчилж чадсангүй.",
          );
        if (data.asset) onAssetUpdated?.(data.asset);
        setEditOpen(false);
      } catch (error) {
        setSaveError(
          error instanceof Error
            ? error.message
            : "Хөрөнгийн мэдээллийг шинэчилж чадсангүй.",
        );
      } finally {
        setSaving(false);
      }
    };

    const securityControls = [
      {
        label: "Нөөцлөлт",
        enabled: asset.backup_enabled,
        partial: false,
        Icon: HardDrive,
      },
      {
        label: "Шифрлэлт",
        enabled: asset.encryption_enabled,
        partial: false,
        Icon: LockKeyhole,
      },
      {
        label: "MFA",
        enabled: asset.mfa_enabled,
        partial: false,
        Icon: KeyRound,
      },
      {
        label: "Лог/SIEM",
        enabled: Boolean(asset.logging_enabled),
        partial: false,
        Icon: Activity,
      },
      {
        label: "EDR",
        enabled: Boolean(asset.edr_enabled),
        partial: false,
        Icon: ShieldAlert,
      },
      {
        label: "Vuln scan",
        enabled: Boolean(asset.vuln_scanning_enabled),
        partial: false,
        Icon: Activity,
      },
    ];

    const criticalityVisuals = getCriticalityVisuals(asset.criticality);
    const AssetTypeIcon = getAssetTypeIcon(asset.asset_type);
    const rtoHours = formatHours(asset.rto_hours);
    const rpoHours = formatHours(asset.rpo_hours);
    const recoveryTarget =
      [rtoHours && `RTO ${rtoHours}`, rpoHours && `RPO ${rpoHours}`]
        .filter(Boolean)
        .join(" / ") || "—";

    const quickStats: { label: string; value: string; Icon: LucideIcon }[] = [
      {
        label: "Ангилал",
        value:
          getLabel(DATA_CLASSIFICATION_LABELS, asset.data_classification) ||
          "Ангилаагүй",
        Icon: ShieldAlert,
      },
      {
        label: "Байрлаж буй бүс",
        value: asset.country
          ? `${asset.country} · ${asset.region || COUNTRY_REGION_MAP[asset.country] || "—"}`
          : asset.region || "—",
        Icon: Globe2,
      },
      { label: "Сэргээх зорилтот цаг", value: recoveryTarget, Icon: Clock3 },
      {
        label: "Байршуулалт",
        value: getLabel(HOSTING_LABELS, asset.hosting) || "—",
        Icon: Cloud,
      },
    ];

    const ownerMeta = [
      asset.business_owner,
      asset.technical_owner,
      asset.department,
    ]
      .filter(Boolean)
      .join(" · ");
    const linkedBusinessProcesses = asset.critical_business_processes ?? [];

    return (
      <Card
        contentEditable={false}
        suppressContentEditableWarning
        className="group overflow-hidden app-card-surface p-0 shadow-sm transition-all duration-200 hover:-translate-y-0.5 hover:shadow-xl cursor-default select-none"
      >
        <div className={`h-1 ${criticalityVisuals.bar}`} />

        <div className="p-4 sm:p-5">
          {/* ── Header ── */}
          <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div className="flex min-w-0 gap-3">
              <div
                className={`relative flex size-10 shrink-0 items-center justify-center rounded-lg border ${criticalityVisuals.iconShell}`}
              >
                <AssetTypeIcon className="size-5" />
                <span
                  className={`absolute -right-1 -top-1 size-2.5 rounded-full border-2 border-card ${criticalityVisuals.signal}`}
                />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                  {asset.asset_code && (
                    <span className="rounded border border-border/70 bg-background/70 px-1.5 py-0.5 font-mono">
                      {asset.asset_code}
                    </span>
                  )}
                  {asset.asset_type && (
                    <span className="inline-flex items-center gap-1 rounded border border-border/70 bg-background/70 px-1.5 py-0.5">
                      <AssetTypeIcon className="size-3" />
                      {getLabel(ASSET_TYPE_LABELS, asset.asset_type)}
                    </span>
                  )}
                </div>
                <h2 className="mt-1 text-lg font-bold leading-tight sm:text-xl">
                  {asset.asset_name}
                </h2>
                {ownerMeta && (
                  <p className="mt-0.5 text-xs text-muted-foreground truncate">
                    {ownerMeta}
                  </p>
                )}
                <div className="mt-0.5 flex flex-wrap gap-1.5 text-[10px] text-muted-foreground">
                  {asset.cmdb_ci_id && (
                    <span className="font-mono rounded bg-muted/60 px-1.5 py-0.5 border border-border/50">
                      {asset.cmdb_ci_id}
                    </span>
                  )}
                  {asset.key_users_customers && (
                    <span className="rounded bg-muted/60 px-1.5 py-0.5 border border-border/50">
                      👥 {asset.key_users_customers}
                    </span>
                  )}
                </div>
              </div>
            </div>

            <div className="flex shrink-0 flex-wrap items-center gap-1.5 sm:justify-end">
              <Badge
                className={`text-xs ${getCriticalityColor(asset.criticality)}`}
              >
                {getLabel(CRITICALITY_LABELS, asset.criticality)}
              </Badge>
              {asset.status && (
                <Badge className={`text-xs ${getStatusColor(asset.status)}`}>
                  {getLabel(STATUS_LABELS, asset.status)}
                </Badge>
              )}
              {asset.internet_exposed && (
                <Badge className="text-xs bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-400">
                  Интернэтэд нээлттэй
                </Badge>
              )}
              <Button
                type="button"
                variant="outline"
                size="icon-sm"
                onClick={() => handleEditOpenChange(true)}
                title="Хөрөнгө засах"
                aria-label="Хөрөнгө засах"
                className="bg-background/80"
              >
                <Pencil className="size-3.5" />
              </Button>
            </div>
          </div>

          {/* ── Quick stats ── */}
          <div className="mt-4 grid grid-cols-2 overflow-hidden rounded-md border border-border/70 bg-background/50 lg:grid-cols-4">
            {quickStats.map((stat, i) => {
              const StatIcon = stat.Icon;
              return (
                <div
                  key={stat.label}
                  className={`min-w-0 p-3 ${i < quickStats.length - 1 ? "border-b border-border/70 lg:border-b-0 lg:border-r" : ""} ${i % 2 === 0 && i < quickStats.length - 2 ? "border-r border-border/70 lg:border-r-0" : ""}`}
                >
                  <div className="mb-1 flex items-center gap-1.5 text-[10px] font-semibold uppercase text-muted-foreground">
                    <StatIcon className="size-3" />
                    {stat.label}
                  </div>
                  <p className="text-xs font-semibold leading-snug">
                    {stat.value}
                  </p>
                </div>
              );
            })}
          </div>

          {/* ── Security controls ── */}
          <div className="mt-3 flex flex-wrap gap-1.5">
            {securityControls.map((ctrl) => {
              const CtrlIcon = ctrl.Icon;
              const StateIcon = ctrl.partial
                ? AlertTriangle
                : ctrl.enabled
                  ? CheckCircle2
                  : XCircle;
              return (
                <span
                  key={ctrl.label}
                  className={`inline-flex items-center gap-1.5 rounded border px-2 py-1 text-[11px] font-semibold ${
                    ctrl.partial
                      ? "border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-900/70 dark:bg-amber-950/35 dark:text-amber-300"
                      : ctrl.enabled
                        ? "border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-900/70 dark:bg-emerald-950/35 dark:text-emerald-300"
                        : "border-red-200 bg-red-50 text-red-800 dark:border-red-900/70 dark:bg-red-950/35 dark:text-red-300"
                  }`}
                >
                  <CtrlIcon className="size-3" />
                  {ctrl.label}
                  <StateIcon className="size-3" />
                </span>
              );
            })}
          </div>

          {(asset.supports_critical_service ||
            linkedBusinessProcesses.length > 0) && (
            <div className="mt-3 rounded-md border border-border/70 bg-background/50 p-3">
              <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase text-muted-foreground">
                <Activity className="size-3.5 text-blue-600" />
                Чухал business process
              </div>
              {linkedBusinessProcesses.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {linkedBusinessProcesses.map((process) => (
                    <span
                      key={process.id}
                      className="rounded border border-blue-500/20 bg-blue-500/10 px-2 py-1 text-xs font-semibold text-blue-700 dark:text-blue-300"
                    >
                      {formatBusinessProcessLabel(process)}
                    </span>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">
                  Тийм, process сонгоогүй байна.
                </p>
              )}
            </div>
          )}
        </div>

        {/* ── Edit dialog ── */}
        <Dialog open={editOpen} onOpenChange={handleEditOpenChange}>
          <DialogContent className="app-readonly top-16 translate-y-0 w-[95vw] sm:w-[92vw] md:w-[90vw] max-w-5xl max-h-[calc(100vh-8.5rem)] overflow-y-auto app-card-surface shadow-2xl duration-150 motion-reduce:duration-0">
            <DialogHeader className="pb-4 border-b border-border">
              <DialogTitle className="text-2xl font-bold bg-linear-to-r from-blue-600 to-cyan-600 bg-clip-text text-transparent">
                Хөрөнгийн мэдээллийг өөрчлөх
              </DialogTitle>
              <DialogDescription className="sr-only">
                Сонгосон хөрөнгийн үндсэн мэдээлэл, эрсдэлийн хүчин зүйлс,
                аюулгүй байдлын хяналт болон хариуцагчийг өөрчилнө.
              </DialogDescription>
            </DialogHeader>

            <form
              onSubmit={handleSubmit}
              className="space-y-5 [&_label]:mb-1.5"
            >
              {/* Basic info */}
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="sm:col-span-2">
                  <Label htmlFor={`asset_name-${asset.id}`}>
                    Хөрөнгийн нэр
                  </Label>
                  <Input
                    id={`asset_name-${asset.id}`}
                    name="asset_name"
                    required
                    value={formData.asset_name}
                    onChange={handleInputChange}
                    className={EDITABLE_FIELD_CLASS}
                  />
                </div>
                <div>
                  <Label htmlFor={`asset_type-${asset.id}`}>
                    Хөрөнгийн төрөл
                  </Label>
                  <select
                    id={`asset_type-${asset.id}`}
                    name="asset_type"
                    value={formData.asset_type}
                    onChange={handleInputChange}
                    className={`${NATIVE_SELECT_CLASS} mt-1`}
                  >
                    <option value="">Сонгоно уу</option>
                    {ASSET_TYPE_OPTIONS.map((t) => (
                      <option key={t} value={t}>
                        {getLabel(ASSET_TYPE_LABELS, t)}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <Label htmlFor={`criticality-${asset.id}`}>
                    Чухал байдлын түвшин
                  </Label>
                  <select
                    id={`criticality-${asset.id}`}
                    name="criticality"
                    required
                    value={formData.criticality}
                    onChange={handleInputChange}
                    className={`${NATIVE_SELECT_CLASS} mt-1`}
                  >
                    <option value="">Сонгоно уу</option>
                    {CRITICALITY_LEVELS.map((l) => (
                      <option key={l} value={l}>
                        {getLabel(CRITICALITY_LABELS, l)}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <Label htmlFor={`data_classification-${asset.id}`}>
                    Өгөгдлийн ангилал
                  </Label>
                  <select
                    id={`data_classification-${asset.id}`}
                    name="data_classification"
                    value={formData.data_classification}
                    onChange={handleInputChange}
                    className={`${NATIVE_SELECT_CLASS} mt-1`}
                  >
                    <option value="">Сонгоно уу</option>
                    {DATA_CLASSIFICATION_OPTIONS.map((c) => (
                      <option key={c} value={c}>
                        {getLabel(DATA_CLASSIFICATION_LABELS, c)}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <Label htmlFor={`status-${asset.id}`}>Төлөв</Label>
                  <select
                    id={`status-${asset.id}`}
                    name="status"
                    value={formData.status}
                    onChange={handleInputChange}
                    className={`${NATIVE_SELECT_CLASS} mt-1`}
                  >
                    {STATUS_OPTIONS.map((s) => (
                      <option key={s} value={s}>
                        {getLabel(STATUS_LABELS, s)}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Risk factors */}
              <div className={EDIT_PANEL_CLASS}>
                <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Эрсдэлийн хүчин зүйлс
                </div>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div>
                    <Label htmlFor={`access_level-${asset.id}`}>
                      Хандалтын хэлбэр
                    </Label>
                    <select
                      id={`access_level-${asset.id}`}
                      name="access_level"
                      value={formData.access_level}
                      onChange={handleInputChange}
                      className={`${NATIVE_SELECT_CLASS} mt-1`}
                    >
                      <option value="">Сонгоно уу</option>
                      {ACCESS_LEVEL_OPTIONS.map((a) => (
                        <option key={a} value={a}>
                          {getLabel(ACCESS_LEVEL_LABELS, a)}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <Label htmlFor={`authentication_method-${asset.id}`}>
                      Баталгаажуулалтын арга
                    </Label>
                    <select
                      id={`authentication_method-${asset.id}`}
                      name="authentication_method"
                      value={formData.authentication_method}
                      onChange={handleInputChange}
                      className={`${NATIVE_SELECT_CLASS} mt-1`}
                    >
                      <option value="">Сонгоно уу</option>
                      {AUTHENTICATION_METHOD_OPTIONS.map((m) => (
                        <option key={m} value={m}>
                          {getLabel(AUTHENTICATION_METHOD_LABELS, m)}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <Label htmlFor={`hosting-${asset.id}`}>
                      Байршуулалтын орчин
                    </Label>
                    <select
                      id={`hosting-${asset.id}`}
                      name="hosting"
                      value={formData.hosting}
                      onChange={handleInputChange}
                      className={`${NATIVE_SELECT_CLASS} mt-1`}
                    >
                      <option value="">Сонгоно уу</option>
                      {getHostingOptions(formData.asset_type).map((h) => (
                        <option key={h} value={h}>
                          {getLabel(HOSTING_LABELS, h)}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <Label htmlFor={`country-${asset.id}`}>
                      Байрлаж буй улс
                    </Label>
                    <select
                      id={`country-${asset.id}`}
                      name="country"
                      value={formData.country}
                      onChange={handleInputChange}
                      className={`${NATIVE_SELECT_CLASS} mt-1`}
                    >
                      <option value="">Сонгоно уу...</option>
                      {COUNTRY_OPTIONS.map((c) => (
                        <option key={c} value={c}>
                          {c}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <Label htmlFor={`region-${asset.id}`}>
                      Байрлаж буй бүс нутаг
                    </Label>
                    {formData.country ? (
                      <div
                        className={`${NATIVE_SELECT_CLASS} mt-1 flex items-center text-muted-foreground`}
                      >
                        {formData.region || "—"}
                      </div>
                    ) : (
                      <select
                        id={`region-${asset.id}`}
                        name="region"
                        value={formData.region}
                        onChange={handleInputChange}
                        className={`${NATIVE_SELECT_CLASS} mt-1`}
                      >
                        <option value="">Сонгоно уу...</option>
                        <option value="Global">Global</option>
                        <option value="Asia Pacific">Asia Pacific</option>
                        <option value="US-East">US-East</option>
                        <option value="US-West">US-West</option>
                        <option value="Europe">Europe</option>
                        <option value="Middle East">Middle East</option>
                        <option value="Africa">Africa</option>
                        <option value="South America">South America</option>
                        <option value="On-Premises">On-Premises</option>
                      </select>
                    )}
                  </div>
                  <div>
                    <Label htmlFor={`key_users_customers-${asset.id}`}>
                      Гол хэрэглэгчид
                    </Label>
                    <Input
                      id={`key_users_customers-${asset.id}`}
                      name="key_users_customers"
                      value={formData.key_users_customers}
                      onChange={handleInputChange}
                      placeholder="жишээ нь: Бүх ажилчид"
                      className={EDITABLE_FIELD_CLASS}
                    />
                  </div>
                  <div>
                    <Label htmlFor={`supports_critical_service-${asset.id}`}>
                      Чухал бизнесийн үйл ажиллагааг дэмждэг эсэх
                    </Label>
                    <select
                      id={`supports_critical_service-${asset.id}`}
                      name="supports_critical_service"
                      value={
                        formData.supports_critical_service ? "true" : "false"
                      }
                      onChange={handleInputChange}
                      className={`${NATIVE_SELECT_CLASS} mt-1`}
                    >
                      <option value="true">Тийм</option>
                      <option value="false">Үгүй</option>
                    </select>
                  </div>
                  {formData.supports_critical_service && (
                    <div className="sm:col-span-2 rounded-md border border-border bg-background/40 p-3">
                      <Label className="mb-2 block text-sm font-medium">
                        Дэмждэг чухал business process
                      </Label>
                      {businessProcessesLoading ? (
                        <p className="text-sm text-muted-foreground">
                          Жагсаалт ачааллаж байна...
                        </p>
                      ) : businessProcesses.length > 0 ? (
                        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                          {businessProcesses.map((process) => (
                            <label
                              key={process.id}
                              className="flex items-center gap-2 rounded-md border border-border bg-background/60 px-3 py-2 text-sm"
                            >
                              <input
                                type="checkbox"
                                className={EDIT_CHOICE_INPUT_CLASS}
                                checked={formData.business_process_ids.includes(
                                  process.id,
                                )}
                                onChange={() =>
                                  handleBusinessProcessToggle(process.id)
                                }
                              />
                              <span className="min-w-0 flex-1">
                                <span className="block">
                                  {formatBusinessProcessLabel(process)}
                                </span>
                                {(process.risk_count ||
                                  toScoreNumber(process.highest_risk_score) >
                                    0) && (
                                  <span className="mt-0.5 block text-xs text-muted-foreground">
                                    Эрсдэл {process.risk_count ?? 0}
                                    {toScoreNumber(process.highest_risk_score) >
                                    0
                                      ? ` · max score ${toScoreNumber(
                                          process.highest_risk_score,
                                        )}`
                                      : ""}
                                  </span>
                                )}
                              </span>
                            </label>
                          ))}
                        </div>
                      ) : (
                        <p className="text-sm text-muted-foreground">
                          Profile хуудас дээр чухал business process бүртгэсний
                          дараа энд сонголт гарна.
                        </p>
                      )}
                    </div>
                  )}
                  <div>
                    <Label htmlFor={`rto_hours-${asset.id}`}>RTO (цаг)</Label>
                    <Input
                      id={`rto_hours-${asset.id}`}
                      name="rto_hours"
                      type="number"
                      step="0.25"
                      min="0"
                      value={formData.rto_hours}
                      onChange={handleInputChange}
                      className={EDITABLE_FIELD_CLASS}
                    />
                  </div>
                  <div>
                    <Label htmlFor={`rpo_hours-${asset.id}`}>RPO (цаг)</Label>
                    <Input
                      id={`rpo_hours-${asset.id}`}
                      name="rpo_hours"
                      type="number"
                      step="0.25"
                      min="0"
                      value={formData.rpo_hours}
                      onChange={handleInputChange}
                      className={EDITABLE_FIELD_CLASS}
                    />
                  </div>
                </div>
              </div>

              {/* Ownership */}
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <div>
                  <Label htmlFor={`business_owner-${asset.id}`}>
                    Бизнесийн хариуцагч
                  </Label>
                  <Input
                    id={`business_owner-${asset.id}`}
                    name="business_owner"
                    value={formData.business_owner}
                    onChange={handleInputChange}
                    className={EDITABLE_FIELD_CLASS}
                  />
                </div>
                <div>
                  <Label htmlFor={`technical_owner-${asset.id}`}>
                    Техникийн хариуцагч
                  </Label>
                  <Input
                    id={`technical_owner-${asset.id}`}
                    name="technical_owner"
                    value={formData.technical_owner}
                    onChange={handleInputChange}
                    className={EDITABLE_FIELD_CLASS}
                  />
                </div>
                <div>
                  <Label htmlFor={`department-${asset.id}`}>Хэлтэс</Label>
                  <Input
                    id={`department-${asset.id}`}
                    name="department"
                    value={formData.department}
                    onChange={handleInputChange}
                    className={EDITABLE_FIELD_CLASS}
                  />
                </div>
              </div>

              {/* Security detail & CMDB */}
              <div className={EDIT_PANEL_CLASS}>
                <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                  Аюулгүй байдлын хяналтын дэлгэрэнгүй
                </p>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <label
                    htmlFor={`logging_enabled-${asset.id}`}
                    className="flex items-center gap-2 cursor-pointer select-none rounded-md border border-border bg-background/40 px-3 py-2 hover:bg-muted/40"
                  >
                    <input
                      type="checkbox"
                      id={`logging_enabled-${asset.id}`}
                      name="logging_enabled"
                      checked={formData.logging_enabled}
                      onChange={handleCheckboxChange}
                      className={EDIT_CHOICE_INPUT_CLASS}
                    />
                    <span className="text-sm font-medium">
                      Лог бүртгэл / SIEM
                    </span>
                  </label>

                  <label
                    htmlFor={`edr_enabled-${asset.id}`}
                    className="flex items-center gap-2 cursor-pointer select-none rounded-md border border-border bg-background/40 px-3 py-2 hover:bg-muted/40"
                  >
                    <input
                      type="checkbox"
                      id={`edr_enabled-${asset.id}`}
                      name="edr_enabled"
                      checked={formData.edr_enabled}
                      onChange={handleCheckboxChange}
                      className={EDIT_CHOICE_INPUT_CLASS}
                    />
                    <span className="text-sm font-medium">
                      EDR / Endpoint Security
                    </span>
                  </label>

                  <label
                    htmlFor={`backup_enabled-${asset.id}`}
                    className="flex items-center gap-2 cursor-pointer select-none rounded-md border border-border bg-background/40 px-3 py-2 hover:bg-muted/40"
                  >
                    <input
                      type="checkbox"
                      id={`backup_enabled-${asset.id}`}
                      name="backup_enabled"
                      checked={formData.backup_enabled}
                      onChange={handleCheckboxChange}
                      className={EDIT_CHOICE_INPUT_CLASS}
                    />
                    <span className="text-sm font-medium">Нөөцлөлт</span>
                  </label>

                  <label
                    htmlFor={`vuln_scanning_enabled-${asset.id}`}
                    className="flex items-center gap-2 cursor-pointer select-none rounded-md border border-border bg-background/40 px-3 py-2 hover:bg-muted/40"
                  >
                    <input
                      type="checkbox"
                      id={`vuln_scanning_enabled-${asset.id}`}
                      name="vuln_scanning_enabled"
                      checked={formData.vuln_scanning_enabled}
                      onChange={handleCheckboxChange}
                      className={EDIT_CHOICE_INPUT_CLASS}
                    />
                    <span className="text-sm font-medium">
                      Эмзэг байдлын скан
                    </span>
                  </label>

                  <label
                    htmlFor={`encryption_enabled-${asset.id}`}
                    className="flex items-center gap-2 cursor-pointer select-none rounded-md border border-border bg-background/40 px-3 py-2 hover:bg-muted/40"
                  >
                    <input
                      type="checkbox"
                      id={`encryption_enabled-${asset.id}`}
                      name="encryption_enabled"
                      checked={formData.encryption_enabled}
                      onChange={handleCheckboxChange}
                      className={EDIT_CHOICE_INPUT_CLASS}
                    />
                    <span className="text-sm font-medium">Шифрлэлт</span>
                  </label>

                  <label
                    htmlFor={`mfa_enabled-${asset.id}`}
                    className="flex items-center gap-2 cursor-pointer select-none rounded-md border border-border bg-background/40 px-3 py-2 hover:bg-muted/40"
                  >
                    <input
                      type="checkbox"
                      id={`mfa_enabled-${asset.id}`}
                      name="mfa_enabled"
                      checked={formData.mfa_enabled}
                      onChange={handleCheckboxChange}
                      className={EDIT_CHOICE_INPUT_CLASS}
                    />
                    <span className="text-sm font-medium">MFA</span>
                  </label>

                  <div className="sm:col-span-2">
                    <Label htmlFor={`cmdb_ci_id-${asset.id}`}>CMDB CI ID</Label>
                    <Input
                      id={`cmdb_ci_id-${asset.id}`}
                      name="cmdb_ci_id"
                      value={formData.cmdb_ci_id}
                      readOnly
                      className={`${EDITABLE_FIELD_CLASS} opacity-60 cursor-default`}
                    />
                  </div>
                  <div className="sm:col-span-2">
                    <Label htmlFor={`notes-${asset.id}`}>Тэмдэглэл</Label>
                    <textarea
                      id={`notes-${asset.id}`}
                      name="notes"
                      value={formData.notes}
                      onChange={handleInputChange}
                      rows={2}
                      placeholder="Нэмэлт мэдээлэл..."
                      className="app-form-field mt-1 w-full rounded-md border px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                </div>
              </div>

              {saveError && (
                <p className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
                  {saveError}
                </p>
              )}

              <DialogFooter className="gap-2 sm:justify-between">
                <Button
                  type="button"
                  variant="outline"
                  onClick={handleRemove}
                  disabled={saving || removing}
                  className="border-red-200 bg-white text-red-600 hover:bg-red-50 hover:text-red-700 dark:border-red-900/70 dark:bg-black dark:text-red-400 dark:hover:bg-red-950/30"
                >
                  <Trash2 className="size-4" />
                  {removing ? "Устгаж байна..." : "Хөрөнгө устгах"}
                </Button>
                <div className="flex items-center gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => handleEditOpenChange(false)}
                    disabled={saving || removing}
                  >
                    Болих
                  </Button>
                  <Button type="submit" disabled={saving || removing}>
                    {saving ? "Хадгалж байна..." : "Өөрчлөлт хадгалах"}
                  </Button>
                </div>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </Card>
    );
  },
);

AssetCard.displayName = "AssetCard";
export default AssetCard;
