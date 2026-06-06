"use client";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  AlertTriangle,
  BarChart3,
  Building2,
  Cloud,
  Database,
  FileText,
  Globe2,
  HardDrive,
  KeyRound,
  Layers,
  LockKeyhole,
  Network,
  Plus,
  RotateCcw,
  Save,
  Server,
  ShieldAlert,
  Users,
  type LucideIcon,
} from "lucide-react";
import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ACCESS_LEVEL_LABELS,
  ACCESS_LEVEL_OPTIONS,
  ASSET_DETAIL_OPTION_LABELS,
  ASSET_TYPE_LABELS,
  ASSET_TYPE_METADATA,
  ASSET_TYPE_OPTIONS,
  type AssetDetailField,
  AUTHENTICATION_METHOD_LABELS,
  AUTHENTICATION_METHOD_OPTIONS,
  COUNTRY_OPTIONS,
  COUNTRY_LABELS,
  COUNTRY_REGION_MAP,
  CRITICALITY_LABELS,
  CRITICALITY_LEVELS,
  DATA_CLASSIFICATION_LABELS,
  DATA_CLASSIFICATION_OPTIONS,
  getHostingOptions,
  getLabel,
  HOSTING_LABELS,
  KEY_USERS_OPTIONS,
  RISK_LEVEL_LABELS,
  REGION_LABELS,
  STATUS_LABELS,
  STATUS_OPTIONS,
} from "./asset-constants";

interface Threat {
  id: number;
  threat_name: string;
  description: string;
  threat_type: string;
  likelihood_level: number;
  potential_impact: string;
  risk_level: string;
  mitigation_notes: string;
  mitigation_notes_mn: string | null;
}

interface AddAssetModalProps {
  onAssetAdded: () => void;
}

interface CriticalBusinessProcess {
  id: number;
  process_code?: string | null;
  process_name: string;
  criticality?: string | null;
  status?: string | null;
  risk_count?: number;
  highest_risk_score?: number | string | null;
  highest_risk_level?: string | null;
}

const ASSET_CHOICE_INPUT_CLASS =
  "app-choice-input h-4 w-4 rounded accent-blue-600";
const ADD_FIELD_CLASS =
  "app-form-field h-11 w-full min-w-0 rounded-md border px-3 text-sm font-medium outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20";
const ADD_TEXTAREA_CLASS =
  "app-form-field min-h-28 w-full min-w-0 rounded-md border px-3 py-2 text-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20";
const ADD_SECTION_CLASS =
  "rounded-lg border border-border bg-background/60 p-4 shadow-sm";
const ADD_SECTION_TITLE_CLASS =
  "mb-4 flex items-center gap-2 text-sm font-semibold text-foreground";
const ADD_SUMMARY_ITEM_CLASS =
  "rounded-md border border-border bg-card px-3 py-2";

const createInitialAssetFormData = () => ({
  asset_type_id: "",
  asset_type: "",
  owner_id: "",
  asset_name: "",
  asset_code: "",
  business_owner: "",
  technical_owner: "",
  department: "",
  data_classification: "",
  access_level: "",
  authentication_method: "",
  supports_critical_service: false,
  business_process_ids: [] as number[],
  hosting: "",
  country: "",
  region: "",
  key_users_customers: "",
  rto_hours: "",
  rpo_hours: "",
  criticality: "",
  internet_exposed: false,
  backup_enabled: false,
  encryption_enabled: false,
  mfa_enabled: false,
  logging_enabled: false,
  edr_enabled: false,
  vuln_scanning_enabled: false,
  cmdb_ci_id: "",
  notes: "",
  asset_details: {} as Record<string, string>,
  status: "Active",
});

const ADD_SECURITY_CONTROL_ITEMS: Array<{
  field: keyof ReturnType<typeof createInitialAssetFormData>;
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

const formatBusinessProcessLabel = (process: CriticalBusinessProcess) =>
  process.process_name;

const toScoreNumber = (value?: number | string | null) => {
  const score = Number(value ?? 0);
  return Number.isFinite(score) ? score : 0;
};

const getAssetIcon = (assetType?: string): LucideIcon => {
  switch (assetType) {
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

const criticalityBadgeClass = (criticality?: string) => {
  if (criticality?.includes("Tier 0"))
    return "border-red-200 bg-red-50 text-red-700";
  if (criticality?.includes("Tier 1"))
    return "border-orange-200 bg-orange-50 text-orange-700";
  if (criticality?.includes("Tier 2"))
    return "border-amber-200 bg-amber-50 text-amber-700";
  if (criticality?.includes("Tier 3"))
    return "border-emerald-200 bg-emerald-50 text-emerald-700";
  return "border-border bg-background text-muted-foreground";
};

const shortCriticalityLabel = (criticality?: string) => {
  if (criticality?.includes("Tier 0")) return "Түвшин 0";
  if (criticality?.includes("Tier 1")) return "Түвшин 1";
  if (criticality?.includes("Tier 2")) return "Түвшин 2";
  if (criticality?.includes("Tier 3")) return "Түвшин 3";
  return "Түвшин сонгоогүй";
};

const statusBadgeClass = (status?: string) => {
  if (status === "Active") return "border-emerald-200 bg-emerald-50 text-emerald-700";
  if (status === "Deprecated") return "border-red-200 bg-red-50 text-red-700";
  if (status === "Inactive") return "border-slate-200 bg-slate-100 text-slate-600";
  return "border-blue-200 bg-blue-50 text-blue-700";
};

function AddAssetModal({ onAssetAdded }: AddAssetModalProps) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [submitError, setSubmitError] = useState("");
  const [threatsLoading, setThreatsLoading] = useState(false);
  const [relatedThreats, setRelatedThreats] = useState<Threat[]>([]);
  const [threatsMessage, setThreatsMessage] = useState("");
  const [businessProcesses, setBusinessProcesses] = useState<
    CriticalBusinessProcess[]
  >([]);
  const [businessProcessesLoading, setBusinessProcessesLoading] =
    useState(false);
  const [businessProcessesFetched, setBusinessProcessesFetched] =
    useState(false);
  const threatCacheRef = useRef<
    Record<string, { threats: Threat[]; message: string }>
  >({});
  const [formData, setFormData] = useState(createInitialAssetFormData);

  const handleInputChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
      const { name, value } = e.target;
      setFormData((prev) => ({ ...prev, [name]: value }));
      setSubmitError("");
    },
    [],
  );

  const handleSelectChange = useCallback((name: string, value: string) => {
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
              asset_type_id: "",
              asset_details: {},
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
                "One-Time Password (OTP)",
                "SMS OTP",
                "Email OTP",
                "Authenticator App",
                "Biometric Authentication",
                "Single Sign-On (SSO)",
                "Active Directory",
              ].includes(value),
            }
          : {}),
      };
    });
    setSubmitError("");
  }, []);

  const handleSecurityControlToggle = useCallback(
    (field: (typeof ADD_SECURITY_CONTROL_ITEMS)[number]["field"]) => {
      setFormData((prev) => {
        const enabled = !Boolean(prev[field]);

        return {
          ...prev,
          [field]: enabled,
          ...(field === "supports_critical_service" && !enabled
            ? { business_process_ids: [] }
            : {}),
        };
      });
      setSubmitError("");
    },
    [],
  );

  const resetForm = useCallback(() => {
    setFormData(createInitialAssetFormData());
    setRelatedThreats([]);
    setThreatsMessage("");
    setThreatsLoading(false);
    setSubmitError("");
  }, []);

  const handleAssetDetailChange = useCallback((name: string, value: string) => {
    setFormData((prev) => ({
      ...prev,
      asset_details: {
        ...prev.asset_details,
        [name]: value,
      },
    }));
    setSubmitError("");
  }, []);

  const handleBusinessProcessToggle = useCallback((processId: number) => {
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
  }, []);

  const fetchBusinessProcesses = useCallback(async () => {
    if (businessProcessesLoading || businessProcessesFetched) return;

    try {
      setBusinessProcessesLoading(true);
      const response = await fetch("/api/business-processes");
      if (!response.ok) {
        throw new Error("Бизнес процессын жагсаалт татаж чадсангүй");
      }
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
      setBusinessProcessesFetched(true);
    } catch (error) {
      console.error("Business process жагсаалт татах үед алдаа гарлаа:", error);
      setBusinessProcesses([]);
    } finally {
      setBusinessProcessesLoading(false);
    }
  }, [businessProcessesFetched, businessProcessesLoading]);

  const displayedThreats = useMemo(
    () => relatedThreats.slice(0, 10),
    [relatedThreats],
  );

  const selectedAssetType = useMemo(
    () => formData.asset_type.trim(),
    [formData.asset_type],
  );
  const selectedAssetMetadata = selectedAssetType
    ? ASSET_TYPE_METADATA[selectedAssetType]
    : undefined;
  const selectedDetailFields = selectedAssetMetadata?.fields ?? [];

  useEffect(() => {
    if (!open || !selectedAssetType) {
      setRelatedThreats([]);
      setThreatsMessage("");
      return;
    }

    const cacheKey = selectedAssetType;
    const cached = threatCacheRef.current[cacheKey];
    if (cached) {
      setRelatedThreats(cached.threats);
      setThreatsMessage(cached.message);
      return;
    }

    const controller = new AbortController();
    const timer = window.setTimeout(async () => {
      try {
        setThreatsLoading(true);
        const threatsUrl = `/api/threats?assetType=${encodeURIComponent(selectedAssetType)}`;
        const response = await fetch(threatsUrl, { signal: controller.signal });

        if (controller.signal.aborted) return;

        if (response.ok) {
          const data = await response.json();
          const nextThreats = data.threats || [];
          const nextMessage = data.message || "";

          threatCacheRef.current[cacheKey] = {
            threats: nextThreats,
            message: nextMessage,
          };

          setRelatedThreats(nextThreats);
          setThreatsMessage(nextMessage);
        } else {
          setRelatedThreats([]);
          setThreatsMessage(
            "Энэ төрлийн хөрөнгөтэй холбоотой аюулыг ачаалж чадсангүй.",
          );
        }
      } catch (error) {
        if (controller.signal.aborted) return;
        console.error("Аюулын мэдээлэл татах үед алдаа гарлаа:", error);
        setRelatedThreats([]);
        setThreatsMessage(
          "Энэ төрлийн хөрөнгөтэй холбоотой аюулыг ачаалж чадсангүй.",
        );
      } finally {
        if (!controller.signal.aborted) {
          setThreatsLoading(false);
        }
      }
    }, 120);

    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [open, selectedAssetType]);

  useEffect(() => {
    if (open) {
      fetchBusinessProcesses();
    }
  }, [open, fetchBusinessProcesses]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      const normalizedAssetType = selectedAssetType;
      if (!normalizedAssetType) {
        throw new Error("Хөрөнгийн төрлийг сонгоно уу.");
      }

      const response = await fetch("/api/assets", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          ...formData,
          asset_type: normalizedAssetType,
          asset_type_id: null,
        }),
      });

      if (!response.ok) {
        let message = "Хөрөнгө үүсгэхэд алдаа гарлаа. Дахин оролдоно уу.";
        try {
          const errorPayload = await response.json();
          if (typeof errorPayload?.error === "string" && errorPayload.error) {
            message = errorPayload.error;
          }
        } catch {
          // Ignore JSON parse failures and fallback to status text below.
        }

        if (message === "Хөрөнгө үүсгэж чадсангүй" && response.statusText) {
          message = response.statusText;
        }

        throw new Error(message);
      }

      await response.json();

      setOpen(false);
      setFormData(createInitialAssetFormData());

      onAssetAdded();
    } catch (error) {
      console.error("Хөрөнгө үүсгэх үед алдаа гарлаа:", error);
      setSubmitError(
        error instanceof Error ? error.message : "Хөрөнгө үүсгэж чадсангүй",
      );
    } finally {
      setLoading(false);
    }
  };

  const handleOpenChange = (newOpen: boolean) => {
    setOpen(newOpen);
    if (!newOpen) {
      setRelatedThreats([]);
      setThreatsMessage("");
      setThreatsLoading(false);
      setSubmitError("");
    }
  };

  const renderAssetDetailField = (field: AssetDetailField) => {
    const value = formData.asset_details[field.name] ?? "";
    const id = `asset_details_${field.name}`;

    if (field.input === "textarea") {
      return (
        <div key={field.name} className="sm:col-span-2">
          <Label htmlFor={id} className="mb-1.5 block text-sm font-medium">
            {field.label}
            {field.required && <span className="text-red-500"> *</span>}
          </Label>
          <textarea
            id={id}
            value={value}
            onChange={(event) =>
              handleAssetDetailChange(field.name, event.target.value)
            }
            required={field.required}
            rows={3}
            placeholder={field.placeholder}
            className={ADD_TEXTAREA_CLASS}
          />
        </div>
      );
    }

    if (field.input === "select") {
      return (
        <div key={field.name}>
          <Label htmlFor={id} className="mb-1.5 block text-sm font-medium">
            {field.label}
            {field.required && <span className="text-red-500"> *</span>}
          </Label>
          <select
            id={id}
            value={value}
            onChange={(event) =>
              handleAssetDetailChange(field.name, event.target.value)
            }
            required={field.required}
            className={ADD_FIELD_CLASS}
          >
            <option value="">Сонгоно уу...</option>
            {(field.options ?? []).map((option) => (
              <option key={option} value={option}>
                {getLabel(ASSET_DETAIL_OPTION_LABELS, option)}
              </option>
            ))}
          </select>
        </div>
      );
    }

    return (
      <div key={field.name}>
        <Label htmlFor={id} className="mb-1.5 block text-sm font-medium">
          {field.label}
          {field.required && <span className="text-red-500"> *</span>}
        </Label>
        <Input
          id={id}
          value={value}
          onChange={(event) =>
            handleAssetDetailChange(field.name, event.target.value)
          }
          required={field.required}
          placeholder={field.placeholder}
          className={ADD_FIELD_CLASS}
        />
      </div>
    );
  };

  const SelectedAssetIcon = getAssetIcon(selectedAssetType);
  const selectedAssetTypeLabel =
    selectedAssetType &&
    (ASSET_TYPE_METADATA[selectedAssetType]?.shortLabel ||
      getLabel(ASSET_TYPE_LABELS, selectedAssetType));
  const enabledSecurityControlCount = ADD_SECURITY_CONTROL_ITEMS.filter(
    ({ field }) => Boolean(formData[field]),
  ).length;
  const securityCompletion =
    (enabledSecurityControlCount / ADD_SECURITY_CONTROL_ITEMS.length) * 100;
  const selectedStatusLabel =
    getLabel(STATUS_LABELS, formData.status) || formData.status || "Идэвхтэй";
  const selectedDataLabel =
    getLabel(DATA_CLASSIFICATION_LABELS, formData.data_classification) ||
    formData.data_classification ||
    "—";
  const selectedHostingLabel =
    getLabel(HOSTING_LABELS, formData.hosting) || formData.hosting || "—";

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>
        <Button className="gap-2">
          <Plus className="h-4 w-4" />
          Хөрөнгө нэмэх
        </Button>
      </DialogTrigger>
      <DialogContent className="app-readonly app-card-surface top-1/2 max-h-[calc(100vh-2rem)] w-[calc(100vw-1.5rem)] max-w-6xl translate-y-[-50%] gap-0 overflow-hidden rounded-lg border p-0 shadow-2xl duration-150 motion-reduce:duration-0 sm:w-[calc(100vw-2rem)]">
        <form onSubmit={handleSubmit} className="flex max-h-[calc(100vh-2rem)] min-h-0 flex-col">
          <DialogHeader className="border-b border-border bg-card/95 px-4 py-4 pr-14 backdrop-blur sm:px-6">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
              <div className="flex min-w-0 items-start gap-3">
                <span className="flex size-12 shrink-0 items-center justify-center rounded-md bg-blue-50 text-blue-700 dark:bg-blue-950/40 dark:text-blue-300">
                  <SelectedAssetIcon className="size-6" />
                </span>
                <div className="min-w-0">
                  <DialogTitle className="text-2xl font-bold leading-8">
                    Хөрөнгө нэмэх
                  </DialogTitle>
                  <DialogDescription className="mt-1 truncate text-sm text-muted-foreground">
                    {formData.asset_name || "Шинэ хөрөнгө"}
                    {formData.asset_code ? ` · ${formData.asset_code}` : ""}
                    {selectedAssetTypeLabel ? ` · ${selectedAssetTypeLabel}` : ""}
                  </DialogDescription>
                </div>
              </div>
              <div className="flex flex-wrap gap-2 lg:justify-end">
                <span
                  className={`rounded border px-2.5 py-1 text-xs font-semibold ${criticalityBadgeClass(
                    formData.criticality,
                  )}`}
                >
                  {shortCriticalityLabel(formData.criticality)}
                </span>
                <span
                  className={`rounded border px-2.5 py-1 text-xs font-semibold ${statusBadgeClass(
                    formData.status,
                  )}`}
                >
                  {selectedStatusLabel}
                </span>
              </div>
            </div>
          </DialogHeader>

          <div className="min-h-0 flex-1 overflow-y-auto px-4 py-5 sm:px-6">
            <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_360px]">
              <div className="space-y-5">
                <section className={ADD_SECTION_CLASS}>
                  <h3 className={ADD_SECTION_TITLE_CLASS}>
                    <Layers className="size-4 text-blue-600" />
                    Үндсэн мэдээлэл
                  </h3>
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                    <label className="sm:col-span-2 text-sm font-medium">
                      <span className="mb-1.5 block">
                        Хөрөнгийн нэр <span className="text-red-500">*</span>
                      </span>
                      <Input
                        id="asset_name"
                        name="asset_name"
                        value={formData.asset_name}
                        onChange={handleInputChange}
                        placeholder="Ажилчдын зөөврийн компьютер"
                        required
                        className={ADD_FIELD_CLASS}
                      />
                    </label>

                    <label className="text-sm font-medium">
                      <span className="mb-1.5 block">Хөрөнгийн код</span>
                      <Input
                        id="asset_code"
                        name="asset_code"
                        value={formData.asset_code}
                        onChange={handleInputChange}
                        placeholder="AST-001"
                        className={ADD_FIELD_CLASS}
                      />
                    </label>

                    <label className="text-sm font-medium">
                      <span className="mb-1.5 block">
                        Хөрөнгийн төрөл <span className="text-red-500">*</span>
                      </span>
                      <select
                        id="asset_type"
                        name="asset_type"
                        required
                        value={formData.asset_type}
                        onChange={(event) =>
                          handleSelectChange("asset_type", event.target.value)
                        }
                        className={ADD_FIELD_CLASS}
                      >
                        <option value="" disabled>
                          Сонгоно уу...
                        </option>
                        {ASSET_TYPE_OPTIONS.map((type) => (
                          <option key={type} value={type}>
                            {getLabel(ASSET_TYPE_LABELS, type)}
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
                        id="criticality"
                        name="criticality"
                        required
                        value={formData.criticality}
                        onChange={(event) =>
                          handleSelectChange("criticality", event.target.value)
                        }
                        className={ADD_FIELD_CLASS}
                      >
                        <option value="" disabled>
                          Сонгоно уу...
                        </option>
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
                        id="data_classification"
                        name="data_classification"
                        value={formData.data_classification}
                        onChange={(event) =>
                          handleSelectChange(
                            "data_classification",
                            event.target.value,
                          )
                        }
                        className={ADD_FIELD_CLASS}
                      >
                        <option value="">Сонгоно уу...</option>
                        {DATA_CLASSIFICATION_OPTIONS.map((classification) => (
                          <option key={classification} value={classification}>
                            {getLabel(
                              DATA_CLASSIFICATION_LABELS,
                              classification,
                            )}
                          </option>
                        ))}
                      </select>
                    </label>

                    <label className="text-sm font-medium">
                      <span className="mb-1.5 block">Төлөв</span>
                      <select
                        id="status"
                        name="status"
                        value={formData.status}
                        onChange={(event) =>
                          handleSelectChange("status", event.target.value)
                        }
                        className={ADD_FIELD_CLASS}
                      >
                        {STATUS_OPTIONS.map((status) => (
                          <option key={status} value={status}>
                            {getLabel(STATUS_LABELS, status)}
                          </option>
                        ))}
                      </select>
                    </label>
                  </div>
                </section>

                {selectedAssetMetadata && (
                  <section className={ADD_SECTION_CLASS}>
                    <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                      <div>
                        <h3 className="flex items-center gap-2 text-sm font-semibold">
                          <SelectedAssetIcon className="size-4 text-blue-600" />
                          {selectedAssetMetadata.label}
                        </h3>
                        <p className="mt-1 text-xs text-muted-foreground">
                          {selectedAssetMetadata.description}
                        </p>
                      </div>
                      <div className="flex max-w-md flex-wrap gap-1.5">
                        {selectedAssetMetadata.examples
                          .slice(0, 4)
                          .map((example) => (
                            <span
                              key={example}
                              className="rounded border border-border bg-card px-2 py-1 text-[11px] text-muted-foreground"
                            >
                              {example}
                            </span>
                          ))}
                      </div>
                    </div>
                    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                      {selectedDetailFields.map(renderAssetDetailField)}
                    </div>
                  </section>
                )}

                <section className={ADD_SECTION_CLASS}>
                  <h3 className={ADD_SECTION_TITLE_CLASS}>
                    <AlertTriangle className="size-4 text-amber-600" />
                    Эрсдэлийн хүчин зүйлс
                  </h3>
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                    <label className="text-sm font-medium">
                      <span className="mb-1.5 block">Хандалтын хэлбэр</span>
                      <select
                        id="access_level"
                        name="access_level"
                        value={formData.access_level}
                        onChange={(event) =>
                          handleSelectChange("access_level", event.target.value)
                        }
                        className={ADD_FIELD_CLASS}
                      >
                        <option value="">Сонгоно уу...</option>
                        {ACCESS_LEVEL_OPTIONS.map((access) => (
                          <option key={access} value={access}>
                            {getLabel(ACCESS_LEVEL_LABELS, access)}
                          </option>
                        ))}
                      </select>
                    </label>

                    <label className="text-sm font-medium">
                      <span className="mb-1.5 block">
                        Танин баталгаажуулах арга
                      </span>
                      <select
                        id="authentication_method"
                        name="authentication_method"
                        value={formData.authentication_method}
                        onChange={(event) =>
                          handleSelectChange(
                            "authentication_method",
                            event.target.value,
                          )
                        }
                        className={ADD_FIELD_CLASS}
                      >
                        <option value="">Сонгоно уу...</option>
                        {AUTHENTICATION_METHOD_OPTIONS.map((method) => (
                          <option key={method} value={method}>
                            {getLabel(AUTHENTICATION_METHOD_LABELS, method)}
                          </option>
                        ))}
                      </select>
                    </label>

                    <label className="text-sm font-medium">
                      <span className="mb-1.5 block">Байршуулалтын орчин</span>
                      <select
                        id="hosting"
                        name="hosting"
                        value={formData.hosting}
                        onChange={(event) =>
                          handleSelectChange("hosting", event.target.value)
                        }
                        className={ADD_FIELD_CLASS}
                      >
                        <option value="">Сонгоно уу...</option>
                        {getHostingOptions(formData.asset_type).map((hosting) => (
                          <option key={hosting} value={hosting}>
                            {getLabel(HOSTING_LABELS, hosting)}
                          </option>
                        ))}
                      </select>
                    </label>

                    <label className="text-sm font-medium">
                      <span className="mb-1.5 block">Байрлаж буй улс</span>
                      <select
                        id="country"
                        name="country"
                        value={formData.country}
                        onChange={(event) =>
                          handleSelectChange("country", event.target.value)
                        }
                        className={ADD_FIELD_CLASS}
                      >
                        <option value="">Сонгоно уу...</option>
                        {COUNTRY_OPTIONS.map((country) => (
                          <option key={country} value={country}>
                            {getLabel(COUNTRY_LABELS, country)}
                          </option>
                        ))}
                      </select>
                    </label>

                    <label className="text-sm font-medium">
                      <span className="mb-1.5 block">Байрлаж буй бүс нутаг</span>
                      {formData.country ? (
                        <div
                          className={`${ADD_FIELD_CLASS} flex items-center text-muted-foreground`}
                        >
                          {getLabel(REGION_LABELS, formData.region) || "—"}
                        </div>
                      ) : (
                        <select
                          id="region"
                          name="region"
                          value={formData.region}
                          onChange={(event) =>
                            handleSelectChange("region", event.target.value)
                          }
                          className={ADD_FIELD_CLASS}
                        >
                          <option value="">Сонгоно уу...</option>
                          {[
                            "Global",
                            "Asia Pacific",
                            "US-East",
                            "US-West",
                            "Europe",
                            "Middle East",
                            "Africa",
                            "South America",
                            "On-Premises",
                          ].map((region) => (
                            <option key={region} value={region}>
                              {getLabel(REGION_LABELS, region)}
                            </option>
                          ))}
                        </select>
                      )}
                    </label>

                    <label className="text-sm font-medium">
                      <span className="mb-1.5 block">Гол хэрэглэгчид</span>
                      <select
                        id="key_users_customers"
                        name="key_users_customers"
                        value={formData.key_users_customers}
                        onChange={(event) =>
                          handleSelectChange(
                            "key_users_customers",
                            event.target.value,
                          )
                        }
                        className={ADD_FIELD_CLASS}
                      >
                        <option value="">Сонгоно уу...</option>
                        {KEY_USERS_OPTIONS.map((option) => (
                          <option key={option} value={option}>
                            {option}
                          </option>
                        ))}
                      </select>
                    </label>

                    <label className="text-sm font-medium">
                      <span className="mb-1.5 block">
                        RTO — Сэргээх зорилтот цаг
                      </span>
                      <Input
                        id="rto_hours"
                        name="rto_hours"
                        type="number"
                        step="0.25"
                        min="0"
                        value={formData.rto_hours}
                        onChange={handleInputChange}
                        placeholder="4"
                        className={ADD_FIELD_CLASS}
                      />
                    </label>

                    <label className="text-sm font-medium">
                      <span className="mb-1.5 block">
                        RPO — Өгөгдөл алдах дээд хязгаар
                      </span>
                      <Input
                        id="rpo_hours"
                        name="rpo_hours"
                        type="number"
                        step="0.25"
                        min="0"
                        value={formData.rpo_hours}
                        onChange={handleInputChange}
                        placeholder="1"
                        className={ADD_FIELD_CLASS}
                      />
                    </label>

                    {formData.supports_critical_service && (
                      <div className="sm:col-span-2 rounded-md border border-border bg-card p-3">
                        <Label className="mb-2 block text-sm font-medium">
                          Дэмждэг чухал бизнес процесс
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
                                className="flex min-h-12 cursor-pointer items-start gap-2 rounded-md border border-border bg-background/60 px-3 py-2 text-sm transition hover:bg-accent/50"
                              >
                                <input
                                  type="checkbox"
                                  className={ASSET_CHOICE_INPUT_CLASS}
                                  checked={formData.business_process_ids.includes(
                                    process.id,
                                  )}
                                  onChange={() =>
                                    handleBusinessProcessToggle(process.id)
                                  }
                                />
                                <span className="min-w-0 flex-1">
                                  <span className="block font-medium">
                                    {formatBusinessProcessLabel(process)}
                                  </span>
                                  {(process.risk_count ||
                                    toScoreNumber(process.highest_risk_score) >
                                      0) && (
                                    <span className="mt-0.5 block text-xs text-muted-foreground">
                                      Эрсдэл {process.risk_count ?? 0}
                                      {toScoreNumber(
                                        process.highest_risk_score,
                                      ) > 0
                                        ? ` · дээд оноо ${toScoreNumber(
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
                            Профайл хуудас дээр чухал бизнес процесс бүртгэсний
                            дараа энд сонголт гарна.
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                </section>

                <section className={ADD_SECTION_CLASS}>
                  <h3 className={ADD_SECTION_TITLE_CLASS}>
                    <Users className="size-4 text-blue-600" />
                    Хариуцагч ба байгууллага
                  </h3>
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                    <label className="text-sm font-medium">
                      <span className="mb-1.5 block">Бизнесийн хариуцагч</span>
                      <Input
                        id="business_owner"
                        name="business_owner"
                        value={formData.business_owner}
                        onChange={handleInputChange}
                        placeholder="МТ газрын захирал"
                        className={ADD_FIELD_CLASS}
                      />
                    </label>
                    <label className="text-sm font-medium">
                      <span className="mb-1.5 block">Техникийн хариуцагч</span>
                      <Input
                        id="technical_owner"
                        name="technical_owner"
                        value={formData.technical_owner}
                        onChange={handleInputChange}
                        placeholder="Ахлах инженер"
                        className={ADD_FIELD_CLASS}
                      />
                    </label>
                    <label className="text-sm font-medium">
                      <span className="mb-1.5 block">Хэлтэс</span>
                      <Input
                        id="department"
                        name="department"
                        value={formData.department}
                        onChange={handleInputChange}
                        placeholder="МТ-ийн хэлтэс"
                        className={ADD_FIELD_CLASS}
                      />
                    </label>
                  </div>
                </section>

                <section className={ADD_SECTION_CLASS}>
                  <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                    <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground">
                      <LockKeyhole className="size-4 text-blue-600" />
                      Аюулгүй байдлын хамрах хүрээ
                    </h3>
                    <span className="text-xs font-medium text-muted-foreground">
                      {enabledSecurityControlCount}/
                      {ADD_SECURITY_CONTROL_ITEMS.length}
                    </span>
                  </div>
                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                    {ADD_SECURITY_CONTROL_ITEMS.map(({ field, label, risk }) => {
                      const enabled = Boolean(formData[field]);

                      return (
                        <button
                          key={field}
                          type="button"
                          onClick={() => handleSecurityControlToggle(field)}
                          className={`flex min-h-12 items-center justify-between gap-3 rounded-md border px-3 py-2 text-left text-sm transition ${
                            enabled
                              ? risk
                                ? "border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-900/70 dark:bg-amber-950/30 dark:text-amber-200"
                                : "border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-900/70 dark:bg-emerald-950/30 dark:text-emerald-200"
                              : "border-border bg-card hover:bg-accent/50"
                          }`}
                        >
                          <span className="min-w-0 font-medium">{label}</span>
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
                    })}
                  </div>
                </section>

                <section className={ADD_SECTION_CLASS}>
                  <label className="block text-sm font-medium">
                    <span className="mb-1.5 flex items-center gap-2">
                      <FileText className="size-4 text-blue-600" />
                      Тэмдэглэл
                    </span>
                    <textarea
                      id="notes"
                      name="notes"
                      value={formData.notes}
                      onChange={handleInputChange}
                      placeholder="Нэмэлт мэдээлэл, тохиргоо, аудитын хугацаа..."
                      className={ADD_TEXTAREA_CLASS}
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
                        {formData.asset_name || "Нэргүй хөрөнгө"}
                      </p>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {selectedAssetTypeLabel || "Ангилал сонгоогүй"}
                      </p>
                    </div>
                  </div>

                  <div className="mt-4 grid grid-cols-2 gap-2">
                    <div className={ADD_SUMMARY_ITEM_CLASS}>
                      <span className="block text-[11px] font-medium uppercase text-muted-foreground">
                        Код
                      </span>
                      <span className="mt-1 block truncate text-sm font-semibold">
                        {formData.asset_code || "—"}
                      </span>
                    </div>
                    <div className={ADD_SUMMARY_ITEM_CLASS}>
                      <span className="block text-[11px] font-medium uppercase text-muted-foreground">
                        Төлөв
                      </span>
                      <span className="mt-1 block truncate text-sm font-semibold">
                        {selectedStatusLabel}
                      </span>
                    </div>
                    <div className={ADD_SUMMARY_ITEM_CLASS}>
                      <span className="block text-[11px] font-medium uppercase text-muted-foreground">
                        RTO
                      </span>
                      <span className="mt-1 block truncate text-sm font-semibold">
                        {formData.rto_hours || "—"}
                      </span>
                    </div>
                    <div className={ADD_SUMMARY_ITEM_CLASS}>
                      <span className="block text-[11px] font-medium uppercase text-muted-foreground">
                        RPO
                      </span>
                      <span className="mt-1 block truncate text-sm font-semibold">
                        {formData.rpo_hours || "—"}
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
                        {ADD_SECURITY_CONTROL_ITEMS.length}
                      </span>
                    </div>
                    <div className="mt-2 h-2 overflow-hidden rounded-full bg-muted">
                      <div
                        className="h-full rounded-full bg-blue-600 transition-all"
                        style={{ width: `${securityCompletion}%` }}
                      />
                    </div>
                  </div>

                  <div className="mt-4 space-y-2 text-sm">
                    <div className="flex items-start justify-between gap-3">
                      <span className="text-muted-foreground">Өгөгдөл</span>
                      <span className="text-right font-medium">
                        {selectedDataLabel}
                      </span>
                    </div>
                    <div className="flex items-start justify-between gap-3">
                      <span className="text-muted-foreground">Байршуулалт</span>
                      <span className="text-right font-medium">
                        {selectedHostingLabel}
                      </span>
                    </div>
                    <div className="flex items-start justify-between gap-3">
                      <span className="text-muted-foreground">Хариуцагч</span>
                      <span className="text-right font-medium">
                        {formData.business_owner || "—"}
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
                      className={`rounded border px-2 py-1 text-xs font-semibold ${criticalityBadgeClass(
                        formData.criticality,
                      )}`}
                    >
                      {shortCriticalityLabel(formData.criticality)}
                    </span>
                    {formData.internet_exposed && (
                      <span className="rounded border border-amber-200 bg-amber-50 px-2 py-1 text-xs font-semibold text-amber-700">
                        Интернэтэд нээлттэй
                      </span>
                    )}
                  </div>
                </div>

                {selectedAssetType && (
                  <div className="rounded-lg border border-border bg-background/70 p-4 text-sm shadow-sm">
                    <div className="mb-3 flex items-center gap-2 font-semibold">
                      <ShieldAlert className="size-4 text-blue-600" />
                      Холбоотой аюулууд
                    </div>
                    {threatsLoading ? (
                      <p className="text-sm text-muted-foreground">
                        Холбоотой аюулуудыг ачаалж байна...
                      </p>
                    ) : relatedThreats.length > 0 ? (
                      <div className="max-h-72 space-y-2 overflow-y-auto pr-1">
                        {displayedThreats.map((threat) => (
                          <div
                            key={threat.id}
                            className="rounded-md border border-border bg-card px-3 py-2"
                          >
                            <div className="mb-1 flex items-center gap-2">
                              <span
                                className={`rounded px-2 py-0.5 text-[11px] font-semibold text-white ${
                                  threat.risk_level === "Critical"
                                    ? "bg-red-600"
                                    : threat.risk_level === "High"
                                      ? "bg-orange-600"
                                      : threat.risk_level === "Medium"
                                        ? "bg-yellow-600"
                                        : "bg-green-600"
                                }`}
                              >
                                {threat.risk_level
                                  ? getLabel(RISK_LEVEL_LABELS, threat.risk_level)
                                  : "Эрсдэл"}
                              </span>
                              <span className="min-w-0 truncate font-medium">
                                {threat.threat_name}
                              </span>
                            </div>
                            <p className="line-clamp-2 text-xs text-muted-foreground">
                              {threat.description}
                            </p>
                          </div>
                        ))}
                        {relatedThreats.length > 10 && (
                          <p className="text-xs text-muted-foreground">
                            Мөн {relatedThreats.length - 10} аюул байна.
                          </p>
                        )}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground">
                        {threatsMessage ||
                          `${getLabel(
                            ASSET_TYPE_LABELS,
                            selectedAssetType,
                          )} төрөлд холбогдсон аюул одоогоор бүртгэгдээгүй байна.`}
                      </p>
                    )}
                  </div>
                )}
              </aside>
            </div>
          </div>

          <div className="border-t border-border bg-card/95 px-4 py-4 backdrop-blur sm:px-6">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
              <div className="min-h-9 flex-1">
                {submitError && (
                  <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-900/70 dark:bg-red-950/30 dark:text-red-300">
                    {submitError}
                  </div>
                )}
              </div>
              <div className="flex flex-wrap justify-end gap-2">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setOpen(false)}
                  className="h-10"
                >
                  Болих
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={resetForm}
                  className="h-10 gap-2"
                >
                  <RotateCcw className="size-4" />
                  Дахин тохируулах
                </Button>
                <Button
                  type="submit"
                  disabled={loading}
                  className="h-10 gap-2 bg-blue-600 hover:bg-blue-700"
                >
                  <Save className="size-4" />
                  {loading ? "Үүсгэж байна..." : "Хөрөнгө үүсгэх"}
                </Button>
              </div>
            </div>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export default memo(AddAssetModal);
