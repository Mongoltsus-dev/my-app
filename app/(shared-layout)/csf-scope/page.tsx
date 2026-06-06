"use client";

import { useAuth } from "@/app/context/AuthContext";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Activity,
  AlertTriangle,
  Bell,
  Building2,
  CheckCircle2,
  ChevronRight,
  CircleDashed,
  Database,
  Globe2,
  LockKeyhole,
  Plus,
  RotateCcw,
  ScanSearch,
  ShieldCheck,
  Trash2,
  Users,
  XCircle,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

type ScopeStatus = "in_scope" | "out_of_scope" | "undecided";

type ScopeRow = {
  subcategory_id: string;
  code: string;
  title: string;
  outcome: string;
  category_code: string;
  category_name: string;
  function_code: string;
  nist_function: string;
  function_name_mn: string;
  is_mandatory: boolean;
  scope_status: ScopeStatus;
  exclusion_reason: string;
  updated_at: string | null;
};

type ScopeDepartment = {
  id: number;
  department_name: string;
  owner_name: string | null;
  criticality: string | null;
  status: string | null;
  notes: string | null;
  asset_count: number;
  process_count: number;
};

type ScopeBusinessProcess = {
  id: number;
  process_code: string | null;
  process_name: string;
  description: string | null;
  business_function: string | null;
  business_owner: string | null;
  criticality: string | null;
  status: string | null;
  rto_hours: string | number | null;
  rpo_hours: string | number | null;
  asset_count: number;
};

type ScopeAsset = {
  id: number;
  asset_name: string;
  asset_code: string | null;
  asset_type: string | null;
  department: string | null;
  criticality: string | null;
  internet_exposed: boolean;
  status: string | null;
  business_owner: string | null;
};

type AssessmentScopeDraft = {
  assessment_name: string;
  assessment_type: string;
  selected_department_ids: number[];
  selected_business_process_ids: number[];
  selected_asset_ids: number[];
  status: string;
};

type ScopeResponse = {
  rows: ScopeRow[];
  departments: ScopeDepartment[];
  business_processes: ScopeBusinessProcess[];
  assets: ScopeAsset[];
  assessment_scope: AssessmentScopeDraft & {
    id: number;
    updated_at: string | null;
  };
  scope_summary?: Record<string, unknown>;
};

// ─── Constants ────────────────────────────────────────────────────────────────

const STEPS = [
  { label: "Хэлтэс", sublabel: "Хамрагдах хэлтэсүүд" },
  { label: "Процессууд", sublabel: "Бизнесийн процесс" },
  { label: "Хөрөнгүүд", sublabel: "Мэдээллийн хөрөнгүүд" },
  { label: "NIST CSF", sublabel: "Дэд ангилал сонгох" },
  { label: "Баталгаажуулах", sublabel: "Мэдээллийг хянах" },
];

const FUNCTION_ORDER = ["GV", "ID", "PR", "DE", "RS", "RC"];
const ROLE_MANAGER = 2;

function getApiError(payload: unknown, fallback: string) {
  if (payload && typeof payload === "object" && "error" in payload) {
    const { error } = payload as { error?: unknown };
    if (typeof error === "string" && error.trim()) return error;
  }

  return fallback;
}

async function parseApiError(response: Response, fallback: string) {
  const payload = await response.json().catch(() => null);
  return getApiError(payload, fallback);
}

// ─── Asset-type → NIST CSF category mapping ──────────────────────────────────
// Maps each asset type (and cross-cutting factors) to the CSF category codes
// that are most relevant. Used to auto-select subcategories in Step 4.
const ASSET_TYPE_CATEGORIES: Record<string, string[]> = {
  Identity: ["PR.AA", "ID.AM", "DE.CM", "GV.RR"],
  Database: ["PR.DS", "PR.AA", "ID.AM", "DE.CM", "ID.RA"],
  Application: ["PR.DS", "PR.AA", "DE.CM", "ID.RA", "PR.PS"],
  Network: ["PR.IR", "DE.CM", "PR.AA", "PR.DS", "DE.AE"],
  "Endpoint Fleet": ["PR.PS", "PR.AT", "DE.CM", "ID.AM", "PR.AA"],
  "SaaS Tenant": ["PR.DS", "GV.SC", "PR.AA", "ID.RA", "DE.CM"],
  Service: ["RC.RP", "PR.IR", "RS.MA", "GV.SC", "DE.CM"],
  Hardware: ["PR.PS", "ID.AM", "DE.CM", "RC.RP"],
};

// Additional categories triggered by cross-cutting properties
const INTERNET_EXPOSED_CATEGORIES = [
  "DE.CM",
  "PR.AA",
  "PR.IR",
  "RS.MA",
  "DE.AE",
];
const HIGH_CRITICALITY_CATEGORIES = [
  "GV.RM",
  "ID.RA",
  "RS.MA",
  "RC.RP",
  "RS.CO",
];
// Baseline categories every org should always have in scope
const BASELINE_CATEGORIES = ["GV.RM", "GV.OC", "ID.AM", "ID.RA"];

/** Derive the set of NIST CSF category codes that apply to a list of assets. */
function deriveRelevantCategories(
  assets: Array<{
    asset_type: string | null;
    criticality: string | null;
    internet_exposed: boolean;
  }>,
): Set<string> {
  const cats = new Set<string>(BASELINE_CATEGORIES);

  for (const asset of assets) {
    // By asset type
    const typeCats = ASSET_TYPE_CATEGORIES[asset.asset_type ?? ""] ?? [];
    typeCats.forEach((c) => cats.add(c));

    // Internet-exposed assets need extra monitoring/response controls
    if (asset.internet_exposed) {
      INTERNET_EXPOSED_CATEGORIES.forEach((c) => cats.add(c));
    }

    // High-criticality assets need governance & recovery controls
    const crit = (asset.criticality ?? "").toLowerCase();
    if (
      crit.includes("tier 0") ||
      crit.includes("tier 1") ||
      crit === "critical" ||
      crit === "high"
    ) {
      HIGH_CRITICALITY_CATEGORIES.forEach((c) => cats.add(c));
    }
  }

  return cats;
}

function deriveAssetScopedSubcategoryIds(
  rows: ScopeRow[],
  assets: ScopeAsset[],
  selectedAssetIds: Set<number>,
) {
  const selectedAssets = assets.filter((asset) =>
    selectedAssetIds.has(asset.id),
  );
  const relevantCategories = deriveRelevantCategories(selectedAssets);
  return new Set(
    rows
      .filter(
        (row) => !row.is_mandatory && relevantCategories.has(row.category_code),
      )
      .map((row) => row.subcategory_id),
  );
}

function recalculateAssetDerivedDraft(
  rows: ScopeRow[],
  currentDraft: Record<
    string,
    { scope_status: ScopeStatus; exclusion_reason: string }
  >,
  previousAutoIds: Set<string>,
  nextAutoIds: Set<string>,
) {
  const nextDraft = { ...currentDraft };

  for (const row of rows) {
    if (row.is_mandatory) {
      nextDraft[row.subcategory_id] = {
        scope_status: "in_scope",
        exclusion_reason: "",
      };
    }
  }

  for (const oldId of previousAutoIds) {
    if (
      !nextAutoIds.has(oldId) &&
      nextDraft[oldId]?.scope_status === "in_scope"
    ) {
      nextDraft[oldId] = {
        scope_status: "undecided",
        exclusion_reason: "",
      };
    }
  }

  let activeAutoCount = 0;
  for (const nextId of nextAutoIds) {
    if (nextDraft[nextId]?.scope_status === "out_of_scope") continue;
    nextDraft[nextId] = {
      scope_status: "in_scope",
      exclusion_reason: "",
    };
    activeAutoCount += 1;
  }

  return { draft: nextDraft, activeAutoCount };
}

const FUNCTION_META: Record<
  string,
  {
    name: string;
    mn: string;
    color: string;
    bg: string;
    icon: React.ElementType;
  }
> = {
  GV: {
    name: "Govern",
    mn: "Засаглал",
    color: "text-violet-700 dark:text-violet-300",
    bg: "bg-violet-500",
    icon: Building2,
  },
  ID: {
    name: "Identify",
    mn: "Тодорхойлох",
    color: "text-sky-700 dark:text-sky-300",
    bg: "bg-sky-500",
    icon: ScanSearch,
  },
  PR: {
    name: "Protect",
    mn: "Хамгаалах",
    color: "text-emerald-700 dark:text-emerald-300",
    bg: "bg-emerald-500",
    icon: ShieldCheck,
  },
  DE: {
    name: "Detect",
    mn: "Илрүүлэх",
    color: "text-amber-700 dark:text-amber-300",
    bg: "bg-amber-500",
    icon: Activity,
  },
  RS: {
    name: "Respond",
    mn: "Хариу арга хэмжээ авах",
    color: "text-rose-700 dark:text-rose-300",
    bg: "bg-rose-500",
    icon: Bell,
  },
  RC: {
    name: "Recover",
    mn: "Сэргээх",
    color: "text-lime-700 dark:text-lime-300",
    bg: "bg-lime-500",
    icon: RotateCcw,
  },
};

const CRITICALITY_COLORS: Record<string, string> = {
  Critical:
    "border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950/40 dark:text-red-300",
  High: "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-800 dark:bg-orange-950/40 dark:text-orange-300",
  Medium:
    "border-yellow-200 bg-yellow-50 text-yellow-700 dark:border-yellow-800 dark:bg-yellow-950/40 dark:text-yellow-300",
  Low: "border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400",
};

// Mongolian display labels for criticality values (DB stores English keys)
const CRITICALITY_LABELS: Record<string, string> = {
  Critical: "Маш өндөр",
  High: "Өндөр",
  Medium: "Дундаж",
  Low: "Бага",
};

const CRITICALITY_OPTIONS = ["Critical", "High", "Medium", "Low"] as const;

const ASSET_CRITICALITY_OPTIONS = [
  "Tier 0 (Life/Safety)",
  "Tier 1 (Mission Critical)",
  "Tier 2 (Business Critical)",
  "Tier 3 (Important)",
];

const ASSET_TYPE_OPTIONS = [
  "Application",
  "Database",
  "Endpoint Fleet",
  "Identity",
  "Network",
  "SaaS Tenant",
  "Service",
  "Storage",
];

// ─── Step Indicator ───────────────────────────────────────────────────────────

function StepIndicator({
  current,
  onNavigate,
}: {
  current: number;
  onNavigate: (step: number) => void;
}) {
  return (
    <div className="flex w-full items-center justify-between overflow-x-auto pb-1">
      {STEPS.map((step, index) => {
        const stepNum = index + 1;
        const done = stepNum < current;
        const active = stepNum === current;
        return (
          <div key={stepNum} className="flex shrink-0 items-center">
            <button
              type="button"
              onClick={() => onNavigate(stepNum)}
              className={`flex items-center gap-2.5 rounded-lg px-3 py-2 text-left transition-colors ${
                active
                  ? "bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-950"
                  : done
                    ? "bg-emerald-50 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-950/30 dark:text-emerald-300"
                    : "text-muted-foreground hover:bg-muted"
              }`}
            >
              <span
                className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-xs font-bold ${
                  active
                    ? "bg-white text-slate-950 dark:bg-slate-950 dark:text-white"
                    : done
                      ? "bg-emerald-500 text-white"
                      : "bg-muted text-muted-foreground"
                }`}
              >
                {done ? <CheckCircle2 className="h-4 w-4" /> : stepNum}
              </span>
              <div className="hidden sm:block">
                <p className="text-xs font-semibold leading-tight">
                  {step.label}
                </p>
                <p
                  className={`text-[10px] leading-tight ${active ? "text-white/70 dark:text-slate-950/70" : "text-muted-foreground"}`}
                >
                  {step.sublabel}
                </p>
              </div>
            </button>
            {index < STEPS.length - 1 && (
              <ChevronRight className="mx-1 h-4 w-4 shrink-0 text-muted-foreground/40" />
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── Step 1: Departments ──────────────────────────────────────────────────────

function Step1Departments({
  departments,
  selected,
  onToggle,
  onAdd,
  onDelete,
  canEdit,
}: {
  departments: ScopeDepartment[];
  selected: Set<number>;
  onToggle: (id: number) => void;
  onAdd: (form: {
    department_name: string;
    owner_name: string;
    criticality: string;
    notes: string;
  }) => Promise<void>;
  onDelete: (id: number) => Promise<void>;
  canEdit: boolean;
}) {
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({
    department_name: "",
    owner_name: "",
    criticality: "Medium",
    notes: "",
  });
  const [adding, setAdding] = useState(false);

  async function handleAdd() {
    if (!form.department_name.trim()) return;
    setAdding(true);
    await onAdd(form);
    setForm({
      department_name: "",
      owner_name: "",
      criticality: "Medium",
      notes: "",
    });
    setShowForm(false);
    setAdding(false);
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold">Хэлтэсүүд</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Үнэлгээнд хамрагдах хэлтэсүүдийг сонгох
        </p>
      </div>

      <div className="flex items-center justify-between">
        <span className="text-sm text-muted-foreground">
          <span className="font-semibold text-slate-950 dark:text-slate-50">
            {selected.size}
          </span>{" "}
          / {departments.length} хэлтэс сонгогдсон
        </span>
        {canEdit && (
          <Button
            size="sm"
            onClick={() => setShowForm(!showForm)}
            variant="outline"
          >
            <Plus className="h-4 w-4" />
            Хэлтэс нэмэх
          </Button>
        )}
      </div>

      {canEdit && showForm && (
        <div className="rounded-xl border bg-slate-50 p-4 dark:bg-slate-900">
          <p className="mb-3 text-sm font-semibold">Шинэ хэлтэс</p>
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs font-medium">
                Хэлтсийн нэр *
              </label>
              <Input
                value={form.department_name}
                onChange={(e) =>
                  setForm((f) => ({ ...f, department_name: e.target.value }))
                }
                placeholder="Жнь: Мэдээллийн технологи"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium">
                Хариуцагч
              </label>
              <Input
                value={form.owner_name}
                onChange={(e) =>
                  setForm((f) => ({ ...f, owner_name: e.target.value }))
                }
                placeholder="Нэр, албан тушаал"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium">
                Ач холбогдол
              </label>
              <select
                value={form.criticality}
                onChange={(e) =>
                  setForm((f) => ({ ...f, criticality: e.target.value }))
                }
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
              >
                {CRITICALITY_OPTIONS.map((c) => (
                  <option key={c} value={c}>
                    {CRITICALITY_LABELS[c]}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium">
                Тэмдэглэл
              </label>
              <Input
                value={form.notes}
                onChange={(e) =>
                  setForm((f) => ({ ...f, notes: e.target.value }))
                }
                placeholder="Нэмэлт мэдээлэл"
              />
            </div>
          </div>
          <div className="mt-3 flex gap-2">
            <Button
              size="sm"
              onClick={handleAdd}
              disabled={adding || !form.department_name.trim()}
            >
              {adding ? "Нэмж байна…" : "Нэмэх"}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setShowForm(false)}
            >
              Болих
            </Button>
          </div>
        </div>
      )}

      {departments.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-xl border border-dashed py-16 text-center">
          <Building2 className="mb-3 h-10 w-10 text-muted-foreground/40" />
          <p className="text-sm font-medium text-muted-foreground">
            Хэлтэс байхгүй байна
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            Дээрх товч дарж хэлтэс нэмнэ үү
          </p>
        </div>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {departments.map((dept) => {
            const isSelected = selected.has(dept.id);
            const critColor =
              CRITICALITY_COLORS[dept.criticality ?? ""] ??
              CRITICALITY_COLORS.Low;
            return (
              <div
                key={dept.id}
                className={`relative rounded-xl border p-4 transition-all ${
                  canEdit ? "cursor-pointer" : "cursor-default"
                } ${
                  isSelected
                    ? "border-emerald-300 bg-emerald-50/60 ring-2 ring-emerald-200 dark:border-emerald-700 dark:bg-emerald-950/20 dark:ring-emerald-800"
                    : "border-slate-200 bg-white hover:border-slate-300 dark:border-slate-800 dark:bg-slate-950"
                }`}
                onClick={() => {
                  if (canEdit) onToggle(dept.id);
                }}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <div
                      className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${
                        isSelected
                          ? "bg-emerald-500"
                          : "bg-slate-100 dark:bg-slate-800"
                      }`}
                    >
                      <Building2
                        className={`h-4 w-4 ${isSelected ? "text-white" : "text-muted-foreground"}`}
                      />
                    </div>
                    <p className="text-sm font-semibold leading-tight truncate">
                      {dept.department_name}
                    </p>
                  </div>
                  {canEdit && (
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onDelete(dept.id);
                      }}
                      className="shrink-0 rounded p-1 text-muted-foreground hover:bg-rose-50 hover:text-rose-600 dark:hover:bg-rose-950/40"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>
                {dept.owner_name && (
                  <p className="mt-2 text-xs text-muted-foreground truncate">
                    <Users className="mr-1 inline h-3 w-3" />
                    {dept.owner_name}
                  </p>
                )}
                <div className="mt-2 flex flex-wrap items-center gap-1.5">
                  {dept.criticality && (
                    <span
                      className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold ${critColor}`}
                    >
                      {CRITICALITY_LABELS[dept.criticality ?? ""] ??
                        dept.criticality}
                    </span>
                  )}
                  <span className="text-[10px] text-muted-foreground">
                    {dept.asset_count} хөрөнгө
                  </span>
                  <span className="text-[10px] text-muted-foreground">
                    {dept.process_count} процесс
                  </span>
                </div>
                {isSelected && (
                  <div className="absolute right-2 top-2">
                    <CheckCircle2 className="h-4 w-4 text-emerald-500" />
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

// ─── Step 2: Business Processes ───────────────────────────────────────────────

function Step2Processes({
  processes,
  selected,
  onToggle,
  onAdd,
  onDelete,
  departments,
  selectedDeptIds,
  canEdit,
}: {
  processes: ScopeBusinessProcess[];
  selected: Set<number>;
  onToggle: (id: number) => void;
  onAdd: (form: {
    process_name: string;
    business_function: string;
    business_owner: string;
    criticality: string;
    description: string;
  }) => Promise<void>;
  onDelete: (id: number) => Promise<void>;
  departments: ScopeDepartment[];
  selectedDeptIds: Set<number>;
  canEdit: boolean;
}) {
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({
    process_name: "",
    business_function: "",
    business_owner: "",
    criticality: "High",
    description: "",
  });
  const [adding, setAdding] = useState(false);

  const selectedDeptNames = useMemo(
    () =>
      new Set(
        departments
          .filter((d) => selectedDeptIds.has(d.id))
          .map((d) => d.department_name.toLowerCase()),
      ),
    [departments, selectedDeptIds],
  );

  async function handleAdd() {
    if (!form.process_name.trim()) return;
    setAdding(true);
    await onAdd(form);
    setForm({
      process_name: "",
      business_function: "",
      business_owner: "",
      criticality: "High",
      description: "",
    });
    setShowForm(false);
    setAdding(false);
  }

  const critBadge = (c: string | null) => {
    const color = CRITICALITY_COLORS[c ?? ""] ?? CRITICALITY_COLORS.Low;
    return (
      <span
        className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold ${color}`}
      >
        {CRITICALITY_LABELS[c ?? ""] ?? c ?? "—"}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold">Бизнес процессууд</h2>
      </div>

      <div className="flex items-center justify-between">
        <span className="text-sm text-muted-foreground">
          <span className="font-semibold text-slate-950 dark:text-slate-50">
            {selected.size}
          </span>{" "}
          / {processes.length} процесс сонгогдсон
        </span>
        {canEdit && (
          <Button
            size="sm"
            onClick={() => setShowForm(!showForm)}
            variant="outline"
          >
            <Plus className="h-4 w-4" />
            Процесс нэмэх
          </Button>
        )}
      </div>

      {canEdit && showForm && (
        <div className="rounded-xl border bg-slate-50 p-4 dark:bg-slate-900">
          <p className="mb-3 text-sm font-semibold">Шинэ бизнесийн процесс</p>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="sm:col-span-2">
              <label className="mb-1 block text-xs font-medium">
                Процессийн нэр *
              </label>
              <Input
                value={form.process_name}
                onChange={(e) =>
                  setForm((f) => ({ ...f, process_name: e.target.value }))
                }
                placeholder="Жнь: Цалин хөлс боловсруулах"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium">Хэлтэс</label>
              <select
                value={form.business_function}
                onChange={(e) =>
                  setForm((f) => ({ ...f, business_function: e.target.value }))
                }
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
              >
                <option value="">— Сонгох —</option>
                {departments
                  .filter((d) => selectedDeptIds.has(d.id))
                  .map((d) => (
                    <option key={d.id} value={d.department_name}>
                      {d.department_name}
                    </option>
                  ))}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium">
                Хариуцагч
              </label>
              <Input
                value={form.business_owner}
                onChange={(e) =>
                  setForm((f) => ({ ...f, business_owner: e.target.value }))
                }
                placeholder="Бизнес процесс хариуцагчийн нэр, албан тушаал"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium">
                Ач холбогдол
              </label>
              <select
                value={form.criticality}
                onChange={(e) =>
                  setForm((f) => ({ ...f, criticality: e.target.value }))
                }
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
              >
                {CRITICALITY_OPTIONS.map((c) => (
                  <option key={c} value={c}>
                    {CRITICALITY_LABELS[c]}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium">Тайлбар</label>
              <Input
                value={form.description}
                onChange={(e) =>
                  setForm((f) => ({ ...f, description: e.target.value }))
                }
                placeholder="Товч тайлбар"
              />
            </div>
          </div>
          <div className="mt-3 flex gap-2">
            <Button
              size="sm"
              onClick={handleAdd}
              disabled={adding || !form.process_name.trim()}
            >
              {adding ? "Нэмж байна…" : "Нэмэх"}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setShowForm(false)}
            >
              Болих
            </Button>
          </div>
        </div>
      )}

      {processes.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-xl border border-dashed py-16 text-center">
          <Database className="mb-3 h-10 w-10 text-muted-foreground/40" />
          <p className="text-sm font-medium text-muted-foreground">
            Процесс байхгүй байна
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            Дээрх товч дарж процесс нэмнэ үү
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {processes.map((proc) => {
            const isSelected = selected.has(proc.id);
            const fnName = proc.business_function;
            const isLinkedToDept =
              fnName && selectedDeptNames.has(fnName.toLowerCase());
            return (
              <div
                key={proc.id}
                className={`flex items-center gap-3 rounded-lg border p-3 transition-all ${
                  canEdit ? "cursor-pointer" : "cursor-default"
                } ${
                  isSelected
                    ? "border-emerald-300 bg-emerald-50/60 ring-1 ring-emerald-200 dark:border-emerald-700 dark:bg-emerald-950/20"
                    : "border-slate-200 bg-white hover:border-slate-300 dark:border-slate-800 dark:bg-slate-950"
                }`}
                onClick={() => {
                  if (canEdit) onToggle(proc.id);
                }}
              >
                <div
                  className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${
                    isSelected
                      ? "bg-emerald-500"
                      : "bg-slate-100 dark:bg-slate-800"
                  }`}
                >
                  {isSelected ? (
                    <CheckCircle2 className="h-4 w-4 text-white" />
                  ) : (
                    <CircleDashed className="h-4 w-4 text-muted-foreground" />
                  )}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-sm font-medium truncate">
                      {proc.process_name}
                    </p>
                    {proc.process_code && (
                      <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-600 dark:bg-slate-800 dark:text-slate-400">
                        {proc.process_code}
                      </span>
                    )}
                    {isLinkedToDept && (
                      <span className="rounded-full border border-sky-200 bg-sky-50 px-2 py-0.5 text-[10px] font-medium text-sky-700 dark:border-sky-800 dark:bg-sky-950/30 dark:text-sky-300">
                        {fnName}
                      </span>
                    )}
                  </div>
                  {proc.description && (
                    <p className="mt-0.5 text-xs text-muted-foreground line-clamp-1">
                      {proc.description}
                    </p>
                  )}
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  {critBadge(proc.criticality)}
                  {canEdit && (
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onDelete(proc.id);
                      }}
                      className="rounded p-1 text-muted-foreground hover:bg-rose-50 hover:text-rose-600 dark:hover:bg-rose-950/40"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── Step 3: Assets ───────────────────────────────────────────────────────────

function Step3Assets({
  assets,
  selected,
  onToggle,
  onAdd,
  departments,
  selectedDeptIds,
  canEdit,
}: {
  assets: ScopeAsset[];
  selected: Set<number>;
  onToggle: (id: number) => void;
  onAdd: (form: {
    asset_name: string;
    asset_type: string;
    department: string;
    criticality: string;
    internet_exposed: boolean;
  }) => Promise<void>;
  departments: ScopeDepartment[];
  selectedDeptIds: Set<number>;
  canEdit: boolean;
}) {
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({
    asset_name: "",
    asset_type: "Application",
    department: "",
    criticality: "Tier 2 (Business Critical)",
    internet_exposed: false,
  });
  const [adding, setAdding] = useState(false);
  const [search, setSearch] = useState("");

  async function handleAdd() {
    if (!form.asset_name.trim()) return;
    setAdding(true);
    await onAdd(form);
    setForm({
      asset_name: "",
      asset_type: "Application",
      department: "",
      criticality: "Tier 2 (Business Critical)",
      internet_exposed: false,
    });
    setShowForm(false);
    setAdding(false);
  }

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return q
      ? assets.filter(
          (a) =>
            a.asset_name.toLowerCase().includes(q) ||
            (a.asset_type ?? "").toLowerCase().includes(q) ||
            (a.department ?? "").toLowerCase().includes(q),
        )
      : assets;
  }, [assets, search]);

  const critBadge = (c: string | null) => {
    const key = c?.includes("Tier 0")
      ? "Critical"
      : c?.includes("Tier 1")
        ? "High"
        : c?.includes("Tier 2")
          ? "Medium"
          : "Low";
    const color = CRITICALITY_COLORS[key] ?? CRITICALITY_COLORS.Low;
    return (
      <span
        className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold ${color}`}
      >
        {CRITICALITY_LABELS[c ?? ""] ?? c ?? "—"}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold">Үндсэн бизнесийн хөрөнгүүд</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Эрсдэлийн үнэлгээнд хамрагдах хөрөнгүүдийг сонгоно уу.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-48">
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Хөрөнгө хайх…"
            className="pl-8"
          />
          <ScanSearch className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
        </div>
        <span className="text-sm text-muted-foreground whitespace-nowrap">
          <span className="font-semibold text-slate-950 dark:text-slate-50">
            {selected.size}
          </span>{" "}
          / {assets.length} сонгогдсон
        </span>
        {canEdit && (
          <Button
            size="sm"
            onClick={() => setShowForm(!showForm)}
            variant="outline"
          >
            <Plus className="h-4 w-4" />
            Хөрөнгө нэмэх
          </Button>
        )}
      </div>

      {canEdit && showForm && (
        <div className="rounded-xl border bg-slate-50 p-4 dark:bg-slate-900">
          <p className="mb-3 text-sm font-semibold">Шинэ хөрөнгө</p>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="sm:col-span-2">
              <label className="mb-1 block text-xs font-medium">
                Хөрөнгийн нэр *
              </label>
              <Input
                value={form.asset_name}
                onChange={(e) =>
                  setForm((f) => ({ ...f, asset_name: e.target.value }))
                }
                placeholder="Жнь: HR Management System"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium">
                Хөрөнгийн төрөл
              </label>
              <select
                value={form.asset_type}
                onChange={(e) =>
                  setForm((f) => ({ ...f, asset_type: e.target.value }))
                }
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
              >
                {ASSET_TYPE_OPTIONS.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium">Хэлтэс</label>
              <select
                value={form.department}
                onChange={(e) =>
                  setForm((f) => ({ ...f, department: e.target.value }))
                }
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
              >
                <option value="">— Сонгох —</option>
                {departments
                  .filter((d) => selectedDeptIds.has(d.id))
                  .map((d) => (
                    <option key={d.id} value={d.department_name}>
                      {d.department_name}
                    </option>
                  ))}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium">
                Ач холбогдлын зэрэглэл
              </label>
              <select
                value={form.criticality}
                onChange={(e) =>
                  setForm((f) => ({ ...f, criticality: e.target.value }))
                }
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
              >
                {ASSET_CRITICALITY_OPTIONS.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex items-center gap-2 pt-5">
              <input
                type="checkbox"
                id="internet_exposed"
                checked={form.internet_exposed}
                onChange={(e) =>
                  setForm((f) => ({ ...f, internet_exposed: e.target.checked }))
                }
                className="h-4 w-4 rounded border-input"
              />
              <label htmlFor="internet_exposed" className="text-sm">
                Интернетэд холбогдсон
              </label>
            </div>
          </div>
          <div className="mt-3 flex gap-2">
            <Button
              size="sm"
              onClick={handleAdd}
              disabled={adding || !form.asset_name.trim()}
            >
              {adding ? "Нэмж байна…" : "Нэмэх"}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setShowForm(false)}
            >
              Болих
            </Button>
          </div>
        </div>
      )}

      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-xl border border-dashed py-16 text-center">
          <Database className="mb-3 h-10 w-10 text-muted-foreground/40" />
          <p className="text-sm font-medium text-muted-foreground">
            {search
              ? "Хайлтад тохирох хөрөнгө олдсонгүй"
              : "Хөрөнгө байхгүй байна"}
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((asset) => {
            const isSelected = selected.has(asset.id);
            return (
              <div
                key={asset.id}
                className={`flex items-center gap-3 rounded-lg border p-3 transition-all ${
                  canEdit ? "cursor-pointer" : "cursor-default"
                } ${
                  isSelected
                    ? "border-emerald-300 bg-emerald-50/60 ring-1 ring-emerald-200 dark:border-emerald-700 dark:bg-emerald-950/20"
                    : "border-slate-200 bg-white hover:border-slate-300 dark:border-slate-800 dark:bg-slate-950"
                }`}
                onClick={() => {
                  if (canEdit) onToggle(asset.id);
                }}
              >
                <div
                  className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${
                    isSelected
                      ? "bg-emerald-500"
                      : "bg-slate-100 dark:bg-slate-800"
                  }`}
                >
                  {isSelected ? (
                    <CheckCircle2 className="h-4 w-4 text-white" />
                  ) : (
                    <Database className="h-4 w-4 text-muted-foreground" />
                  )}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-sm font-medium truncate">
                      {asset.asset_name}
                    </p>
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
                  {asset.department && (
                    <p className="mt-0.5 text-xs text-muted-foreground">
                      {asset.department}
                    </p>
                  )}
                </div>
                <div className="shrink-0">{critBadge(asset.criticality)}</div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── Step 4: NIST CSF Subcategories ──────────────────────────────────────────

function Step4NistCsf({
  rows,
  draft,
  onChange,
  canEdit,
}: {
  rows: ScopeRow[];
  draft: Record<
    string,
    { scope_status: ScopeStatus; exclusion_reason: string }
  >;
  onChange: (id: string, status: ScopeStatus, reason?: string) => void;
  canEdit: boolean;
}) {
  const [expandedFns, setExpandedFns] = useState<Set<string>>(
    new Set(FUNCTION_ORDER),
  );
  const [search, setSearch] = useState("");

  const grouped = useMemo(() => {
    const q = search.toLowerCase();
    const filteredRows = q
      ? rows.filter(
          (r) =>
            r.subcategory_id.toLowerCase().includes(q) ||
            r.title.toLowerCase().includes(q),
        )
      : rows;

    const fnMap = new Map<
      string,
      { rows: ScopeRow[]; byCategory: Map<string, ScopeRow[]> }
    >();
    for (const row of filteredRows) {
      if (!fnMap.has(row.function_code)) {
        fnMap.set(row.function_code, { rows: [], byCategory: new Map() });
      }
      const fn = fnMap.get(row.function_code)!;
      fn.rows.push(row);
      if (!fn.byCategory.has(row.category_code))
        fn.byCategory.set(row.category_code, []);
      fn.byCategory.get(row.category_code)!.push(row);
    }
    return fnMap;
  }, [rows, search]);

  const inScopeCount = useMemo(
    () =>
      Object.values(draft).filter((d) => d.scope_status === "in_scope").length,
    [draft],
  );

  function toggleFn(code: string) {
    setExpandedFns((prev) => {
      const next = new Set(prev);
      if (next.has(code)) {
        next.delete(code);
      } else {
        next.add(code);
      }
      return next;
    });
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold">
          Эрсдэлийн үнэлгээнд хамрагдах дэд ангилалуудыг сонгоно уу.
        </h2>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-48">
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Код эсвэл нэрээр хайх…"
            className="pl-8"
          />
          <ScanSearch className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
        </div>
        <div className="flex items-center gap-2 rounded-lg border bg-white px-3 py-2 dark:bg-slate-950">
          <CheckCircle2 className="h-4 w-4 text-emerald-500" />
          <span className="text-sm font-semibold">{inScopeCount}</span>
          <span className="text-xs text-muted-foreground">/ {rows.length}</span>
        </div>
      </div>

      <div className="space-y-3">
        {FUNCTION_ORDER.map((fnCode) => {
          const meta = FUNCTION_META[fnCode];
          const fnData = grouped.get(fnCode);
          if (!fnData) return null;
          const Icon = meta.icon;
          const isExpanded = expandedFns.has(fnCode);
          const fnInScope = fnData.rows.filter((r) => {
            const d = draft[r.subcategory_id];
            return d?.scope_status === "in_scope" || r.is_mandatory;
          }).length;

          return (
            <div key={fnCode} className="overflow-hidden rounded-xl border">
              <button
                type="button"
                onClick={() => toggleFn(fnCode)}
                className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-muted/50"
              >
                <div
                  className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${meta.bg}`}
                >
                  <Icon className="h-4 w-4 text-white" />
                </div>
                <div className="flex-1 min-w-0">
                  <span className="text-sm font-semibold">
                    {fnCode} — {meta.mn}
                  </span>
                  <span className="ml-2 text-xs text-muted-foreground">
                    {meta.name}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`text-xs font-semibold ${meta.color}`}>
                    {fnInScope} / {fnData.rows.length}
                  </span>
                  <ChevronRight
                    className={`h-4 w-4 text-muted-foreground transition-transform ${isExpanded ? "rotate-90" : ""}`}
                  />
                </div>
              </button>

              {isExpanded && (
                <div className="border-t">
                  {Array.from(fnData.byCategory.entries()).map(
                    ([catCode, catRows]) => (
                      <div key={catCode}>
                        <div className="bg-muted/30 px-4 py-2">
                          <span className="text-xs font-semibold text-muted-foreground">
                            {catCode} — {catRows[0]?.category_name}
                          </span>
                        </div>
                        <div className="divide-y">
                          {catRows.map((row) => {
                            const d = draft[row.subcategory_id] ?? {
                              scope_status: row.scope_status,
                              exclusion_reason: "",
                            };
                            const status = row.is_mandatory
                              ? "in_scope"
                              : d.scope_status;
                            const missingReason =
                              status === "out_of_scope" &&
                              !d.exclusion_reason.trim();

                            return (
                              <div
                                key={row.subcategory_id}
                                className="px-4 py-3"
                              >
                                <div className="grid gap-3 xl:grid-cols-[1fr_280px]">
                                  <div className="min-w-0">
                                    <div className="flex flex-wrap items-center gap-2">
                                      <span className="rounded bg-blue-50 px-2 py-0.5 font-mono text-xs font-bold text-blue-700 dark:bg-blue-950/40 dark:text-blue-300">
                                        {row.subcategory_id}
                                      </span>
                                      {row.is_mandatory && (
                                        <Badge className="gap-1 rounded-md border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
                                          <LockKeyhole className="h-3 w-3" />
                                          Заавал
                                        </Badge>
                                      )}
                                    </div>
                                    <p className="mt-1 text-sm font-medium">
                                      {row.title}
                                    </p>
                                    <p className="mt-0.5 text-xs text-muted-foreground line-clamp-2">
                                      {row.outcome}
                                    </p>
                                  </div>

                                  <div className="space-y-2">
                                    {row.is_mandatory ? (
                                      <div className="flex h-9 items-center justify-center gap-1.5 rounded-md border border-amber-200 bg-amber-50 text-xs font-semibold text-amber-800 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
                                        <LockKeyhole className="h-3.5 w-3.5" />
                                        Заавал орно
                                      </div>
                                    ) : (
                                      <div className="grid grid-cols-3 gap-0.5 rounded-md border bg-background p-0.5">
                                        {(
                                          [
                                            "in_scope",
                                            "out_of_scope",
                                            "undecided",
                                          ] as ScopeStatus[]
                                        ).map((s) => {
                                          const labels: Record<
                                            ScopeStatus,
                                            string
                                          > = {
                                            in_scope: "Оруулах",
                                            out_of_scope: "Хасах",
                                            undecided: "Дараа",
                                          };
                                          const icons: Record<
                                            ScopeStatus,
                                            React.ElementType
                                          > = {
                                            in_scope: CheckCircle2,
                                            out_of_scope: XCircle,
                                            undecided: CircleDashed,
                                          };
                                          const BtnIcon = icons[s];
                                          return (
                                            <button
                                              key={s}
                                              type="button"
                                              disabled={!canEdit}
                                              onClick={() =>
                                                onChange(row.subcategory_id, s)
                                              }
                                              className={`flex h-8 items-center justify-center gap-1 rounded px-1 text-xs font-medium transition-colors ${
                                                status === s
                                                  ? s === "in_scope"
                                                    ? "bg-emerald-500 text-white dark:bg-emerald-600"
                                                    : s === "out_of_scope"
                                                      ? "bg-rose-500 text-white dark:bg-rose-600"
                                                      : "bg-amber-400 text-amber-900 dark:bg-amber-500"
                                                  : "text-muted-foreground hover:bg-muted"
                                              }`}
                                            >
                                              <BtnIcon className="h-3.5 w-3.5 shrink-0" />
                                              <span className="hidden sm:block truncate">
                                                {labels[s]}
                                              </span>
                                            </button>
                                          );
                                        })}
                                      </div>
                                    )}
                                    {status === "out_of_scope" &&
                                      !row.is_mandatory && (
                                        <div>
                                          <Textarea
                                            value={d.exclusion_reason}
                                            disabled={!canEdit}
                                            onChange={(e) =>
                                              onChange(
                                                row.subcategory_id,
                                                "out_of_scope",
                                                e.target.value,
                                              )
                                            }
                                            rows={2}
                                            placeholder="Хамрахгүй шалтгаан…"
                                            className="min-h-16 resize-y text-xs"
                                          />
                                          {missingReason && (
                                            <p className="mt-1 flex items-center gap-1 text-[11px] text-rose-600 dark:text-rose-400">
                                              <AlertTriangle className="h-3 w-3" />
                                              Шалтгаан оруулна уу
                                            </p>
                                          )}
                                        </div>
                                      )}
                                  </div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    ),
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Step 5: Review ───────────────────────────────────────────────────────────

function Step5Review({
  departments,
  selectedDeptIds,
  processes,
  selectedProcessIds,
  assets,
  selectedAssetIds,
  rows,
  draft,
}: {
  departments: ScopeDepartment[];
  selectedDeptIds: Set<number>;
  processes: ScopeBusinessProcess[];
  selectedProcessIds: Set<number>;
  assets: ScopeAsset[];
  selectedAssetIds: Set<number>;
  rows: ScopeRow[];
  draft: Record<
    string,
    { scope_status: ScopeStatus; exclusion_reason: string }
  >;
}) {
  const selectedDepts = departments.filter((d) => selectedDeptIds.has(d.id));
  const selectedProcs = processes.filter((p) => selectedProcessIds.has(p.id));
  const selectedAssets = assets.filter((a) => selectedAssetIds.has(a.id));
  const inScopeRows = rows.filter((r) => {
    const d = draft[r.subcategory_id];
    return r.is_mandatory || d?.scope_status === "in_scope";
  });
  const missingReasons = rows.filter((r) => {
    const d = draft[r.subcategory_id];
    return (
      !r.is_mandatory &&
      d?.scope_status === "out_of_scope" &&
      !d.exclusion_reason.trim()
    );
  });
  const criticalAssets = selectedAssets.filter(
    (a) =>
      (a.criticality ?? "").toLowerCase().includes("tier 0") ||
      (a.criticality ?? "").toLowerCase().includes("tier 1"),
  );
  const coveragePct = rows.length
    ? Math.round((inScopeRows.length / rows.length) * 100)
    : 0;
  const functionSummaries = FUNCTION_ORDER.map((fnCode) => {
    const meta = FUNCTION_META[fnCode];
    const fnRows = rows.filter((r) => r.function_code === fnCode);
    const fnInScope = fnRows.filter((r) => {
      const d = draft[r.subcategory_id];
      return r.is_mandatory || d?.scope_status === "in_scope";
    }).length;
    const pct = fnRows.length
      ? Math.round((fnInScope / fnRows.length) * 100)
      : 0;
    return { fnCode, meta, fnRows, fnInScope, pct };
  });

  const tiles = [
    {
      label: "Хэлтэс",
      value: selectedDepts.length,
      total: departments.length,
      sub: "хамрах нэгж",
      icon: Building2,
      color: "bg-violet-500",
      text: "text-violet-700 dark:text-violet-300",
      bg: "bg-violet-50 border-violet-100 dark:bg-violet-950/30 dark:border-violet-900",
    },
    {
      label: "Процесс",
      value: selectedProcs.length,
      total: processes.length,
      sub: "critical workflow",
      icon: Database,
      color: "bg-sky-500",
      text: "text-sky-700 dark:text-sky-300",
      bg: "bg-sky-50 border-sky-100 dark:bg-sky-950/30 dark:border-sky-900",
    },
    {
      label: "Хөрөнгө",
      value: selectedAssets.length,
      total: assets.length,
      sub: `${criticalAssets.length} критик`,
      icon: ShieldCheck,
      color: "bg-emerald-500",
      text: "text-emerald-700 dark:text-emerald-300",
      bg: "bg-emerald-50 border-emerald-100 dark:bg-emerald-950/30 dark:border-emerald-900",
    },
    {
      label: "NIST CSF дэд ангилал",
      value: inScopeRows.length,
      total: rows.length,
      sub: `${coveragePct}% coverage`,
      icon: CheckCircle2,
      color: "bg-amber-500",
      text: "text-amber-700 dark:text-amber-300",
      bg: "bg-amber-50 border-amber-100 dark:bg-amber-950/30 dark:border-amber-900",
    },
  ];

  return (
    <div className="space-y-5">
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-950">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-600 text-white">
                <CheckCircle2 className="h-5 w-5" />
              </div>
              <div>
                <h2 className="text-xl font-bold">Баталгаажуулах</h2>
              </div>
            </div>
          </div>
          <div className="rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 dark:border-slate-800 dark:bg-slate-900/60">
            <div className="flex items-center justify-between gap-6">
              <span className="text-xs font-medium text-muted-foreground">
                Стандартын хамрах хүрээ
              </span>
              <span className="text-lg font-bold text-slate-950 dark:text-slate-50">
                {coveragePct}%
              </span>
            </div>
            <div className="mt-2 h-2 w-44 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
              <div
                className="h-full rounded-full bg-blue-600"
                style={{ width: `${coveragePct}%` }}
              />
            </div>
          </div>
        </div>
      </div>

      {missingReasons.length > 0 && (
        <div className="flex items-start gap-3 rounded-lg border border-rose-200 bg-rose-50 p-4 dark:border-rose-800 dark:bg-rose-950/20">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-rose-600" />
          <div>
            <p className="text-sm font-semibold text-rose-700 dark:text-rose-400">
              {missingReasons.length} дэд ангилалд хасах шалтгаан оруулаагүй
              байна
            </p>
            <p className="mt-0.5 text-xs text-rose-600 dark:text-rose-400">
              4-р алхам руу буцаж шалтгааныг оруулна уу.
            </p>
          </div>
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {tiles.map((tile) => {
          const Icon = tile.icon;
          return (
            <div
              key={tile.label}
              className={`rounded-xl border p-4 shadow-sm ${tile.bg}`}
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-xs font-semibold text-muted-foreground">
                    {tile.label}
                  </p>
                  <div className="mt-2 flex items-end gap-1.5">
                    <p
                      className={`text-3xl font-bold leading-none ${tile.text}`}
                    >
                      {tile.value}
                    </p>
                    <p className="pb-0.5 text-xs text-muted-foreground">
                      / {tile.total}
                    </p>
                  </div>
                  <p className="mt-2 text-xs text-muted-foreground">
                    {tile.sub}
                  </p>
                </div>
                <div
                  className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${tile.color}`}
                >
                  <Icon className="h-5 w-5 text-white" />
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-950">
          <div className="mb-3 flex items-center justify-between gap-3">
            <h3 className="flex items-center gap-2 text-sm font-semibold">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-violet-50 text-violet-600 dark:bg-violet-950/40 dark:text-violet-300">
                <Building2 className="h-4 w-4" />
              </span>
              Сонгогдсон хэлтэснүүд
            </h3>
            <Badge className="bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300">
              {selectedDepts.length}
            </Badge>
          </div>
          {selectedDepts.length === 0 ? (
            <p className="rounded-lg border border-dashed border-slate-200 p-4 text-center text-xs text-muted-foreground dark:border-slate-800">
              Хэлтэс сонгоогүй байна
            </p>
          ) : (
            <div className="space-y-2">
              {selectedDepts.map((d) => (
                <div
                  key={d.id}
                  className="flex items-center justify-between gap-3 rounded-lg border border-slate-100 bg-slate-50 px-3 py-2 text-sm dark:border-slate-800 dark:bg-slate-900/60"
                >
                  <span className="truncate font-medium">
                    {d.department_name}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {d.asset_count} хөрөнгө
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-950">
          <div className="mb-3 flex items-center justify-between gap-3">
            <h3 className="flex items-center gap-2 text-sm font-semibold">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-50 text-sky-600 dark:bg-sky-950/40 dark:text-sky-300">
                <Database className="h-4 w-4" />
              </span>
              Сонгогдсон процессууд
            </h3>
            <Badge className="bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300">
              {selectedProcs.length}
            </Badge>
          </div>
          {selectedProcs.length === 0 ? (
            <p className="rounded-lg border border-dashed border-slate-200 p-4 text-center text-xs text-muted-foreground dark:border-slate-800">
              Процесс сонгоогүй байна
            </p>
          ) : (
            <div className="max-h-52 space-y-2 overflow-y-auto pr-1">
              {selectedProcs.map((p) => (
                <div
                  key={p.id}
                  className="flex items-center justify-between gap-3 rounded-lg border border-slate-100 bg-slate-50 px-3 py-2 text-sm dark:border-slate-800 dark:bg-slate-900/60"
                >
                  <span className="min-w-0 truncate font-medium">
                    {p.process_name}
                  </span>
                  <span
                    className={`ml-2 shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-semibold ${CRITICALITY_COLORS[p.criticality ?? ""] ?? CRITICALITY_COLORS.Low}`}
                  >
                    {p.criticality}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-950">
          <div className="mb-3 flex items-center justify-between gap-3">
            <h3 className="flex items-center gap-2 text-sm font-semibold">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-50 text-emerald-600 dark:bg-emerald-950/40 dark:text-emerald-300">
                <ShieldCheck className="h-4 w-4" />
              </span>
              Сонгогдсон хөрөнгүүд
            </h3>
            <Badge className="bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300">
              {selectedAssets.length}
            </Badge>
          </div>
          {selectedAssets.length === 0 ? (
            <p className="rounded-lg border border-dashed border-slate-200 p-4 text-center text-xs text-muted-foreground dark:border-slate-800">
              Хөрөнгө сонгоогүй байна
            </p>
          ) : (
            <>
              {criticalAssets.length > 0 && (
                <p className="mb-3 inline-flex rounded-full bg-rose-50 px-2.5 py-1 text-[11px] font-semibold text-rose-700 ring-1 ring-rose-100 dark:bg-rose-950/40 dark:text-rose-300 dark:ring-rose-900">
                  {criticalAssets.length} критик хөрөнгө сонгогдсон
                </p>
              )}
              <div className="max-h-52 space-y-2 overflow-y-auto pr-1">
                {selectedAssets.map((a) => (
                  <div
                    key={a.id}
                    className="flex items-center justify-between gap-3 rounded-lg border border-slate-100 bg-slate-50 px-3 py-2 text-sm dark:border-slate-800 dark:bg-slate-900/60"
                  >
                    <span className="min-w-0 truncate font-medium">
                      {a.asset_name}
                    </span>
                    <span className="ml-2 shrink-0 rounded-md bg-white px-2 py-0.5 text-xs text-muted-foreground ring-1 ring-slate-200 dark:bg-slate-950 dark:ring-slate-800">
                      {a.asset_type}
                    </span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-950">
          <div className="mb-3 flex items-center justify-between gap-3">
            <h3 className="flex items-center gap-2 text-sm font-semibold">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-amber-50 text-amber-600 dark:bg-amber-950/40 dark:text-amber-300">
                <CheckCircle2 className="h-4 w-4" />
              </span>
              NIST CSF функцүүд
            </h3>
            <Badge className="bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300">
              {inScopeRows.length}/{rows.length}
            </Badge>
          </div>
          <div className="space-y-3">
            {functionSummaries.map(
              ({ fnCode, meta, fnRows, fnInScope, pct }) => {
                const Icon = meta.icon;
                return (
                  <div
                    key={fnCode}
                    className="rounded-lg border border-slate-100 bg-slate-50 px-3 py-2 dark:border-slate-800 dark:bg-slate-900/60"
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${meta.bg}`}
                      >
                        <Icon className="h-4 w-4 text-white" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center justify-between gap-3">
                          <span className="truncate text-sm font-semibold">
                            {meta.mn}
                          </span>
                          <span className={`text-xs font-bold ${meta.color}`}>
                            {fnInScope}/{fnRows.length}
                          </span>
                        </div>
                        <div className="mt-2 flex items-center gap-2">
                          <div className="h-2 flex-1 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
                            <div
                              className={`h-full rounded-full ${meta.bg}`}
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                          <span className="w-8 text-right text-[11px] font-semibold text-muted-foreground">
                            {pct}%
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              },
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function CsfScopePage() {
  const { user } = useAuth();
  const canManageScope = Number(user?.role ?? 0) === ROLE_MANAGER;
  const [data, setData] = useState<ScopeResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [step, setStep] = useState(1);
  const [message, setMessage] = useState<{
    tone: "success" | "error";
    text: string;
  } | null>(null);

  // Selections
  const [selectedDeptIds, setSelectedDeptIds] = useState<Set<number>>(
    new Set(),
  );
  const [selectedProcessIds, setSelectedProcessIds] = useState<Set<number>>(
    new Set(),
  );
  const [selectedAssetIds, setSelectedAssetIds] = useState<Set<number>>(
    new Set(),
  );

  // NIST CSF draft
  const [nistDraft, setNistDraft] = useState<
    Record<string, { scope_status: ScopeStatus; exclusion_reason: string }>
  >({});

  // editMode: true while the user is editing an already-finalized scope
  const [editMode, setEditMode] = useState(false);

  const [autoScopedIds, setAutoScopedIds] = useState<Set<string>>(new Set());

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/csf-scope", {
        credentials: "include",
      });
      const payload = (await res.json()) as ScopeResponse;
      if (!res.ok) throw new Error("Мэдээлэл уншиж чадсангүй");
      setData(payload);

      // Init selections from saved assessment scope
      const scope = payload.assessment_scope;

      // Filter saved IDs against currently-existing departments (stale IDs from
      // deleted English departments would otherwise show a wrong counter)
      const validDeptIdSet = new Set(payload.departments.map((d) => d.id));
      const savedDeptIds = (scope.selected_department_ids ?? [])
        .map(Number)
        .filter((id) => validDeptIdSet.has(id));

      if (savedDeptIds.length > 0) {
        setSelectedDeptIds(new Set(savedDeptIds));
      } else {
        // First visit (or all saved IDs were stale) — auto-select 6 defaults
        const PRE_SELECTED_DEPT_NAMES = new Set([
          "Мэдээллийн технологийн хэлтэс",
          "Санхүүгийн хэлтэс",
          "Хүний нөөцийн хэлтэс",
          "Үйл ажиллагааны хэлтэс",
          "Худалдан авалт / Нийлүүлэгчийн удирдлагын хэлтэс",
          "Удирдлага",
        ]);
        setSelectedDeptIds(
          new Set(
            payload.departments
              .filter((d) => PRE_SELECTED_DEPT_NAMES.has(d.department_name))
              .map((d) => d.id),
          ),
        );
      }
      setSelectedProcessIds(
        new Set((scope.selected_business_process_ids ?? []).map(Number)),
      );
      const savedAssetIds = new Set(
        (scope.selected_asset_ids ?? []).map(Number),
      );
      setSelectedAssetIds(savedAssetIds);

      // Init NIST draft
      const initDraft: Record<
        string,
        { scope_status: ScopeStatus; exclusion_reason: string }
      > = {};
      for (const row of payload.rows) {
        initDraft[row.subcategory_id] = {
          scope_status: row.scope_status,
          exclusion_reason: row.exclusion_reason ?? "",
        };
      }
      const nextAutoIds = deriveAssetScopedSubcategoryIds(
        payload.rows,
        payload.assets,
        savedAssetIds,
      );
      const recalculated = recalculateAssetDerivedDraft(
        payload.rows,
        initDraft,
        nextAutoIds,
        nextAutoIds,
      );
      setAutoScopedIds(nextAutoIds);
      setNistDraft(recalculated.draft);
    } catch {
      setMessage({ tone: "error", text: "Мэдээлэл уншиж чадсангүй" });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // ── Save current step selections ──────────────────────────────────────────

  async function saveSelections() {
    if (!canManageScope) {
      setMessage({
        tone: "error",
        text: "Зөвхөн удирдлага хамрах хүрээг өөрчлөх эрхтэй",
      });
      return;
    }

    setSaving(true);
    setMessage(null);
    try {
      const res = await fetch("/api/csf-scope", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          assessment_scope: {
            assessment_name:
              data?.assessment_scope.assessment_name ??
              "2026 SME Cybersecurity Risk Assessment",
            assessment_type:
              data?.assessment_scope.assessment_type ?? "Asset-based",
            selected_department_ids: Array.from(selectedDeptIds),
            selected_business_process_ids: Array.from(selectedProcessIds),
            selected_asset_ids: Array.from(selectedAssetIds),
            status: "Draft",
          },
        }),
      });
      if (!res.ok)
        throw new Error(await parseApiError(res, "Хадгалж чадсангүй"));
      const payload = (await res.json()) as ScopeResponse;
      setData(payload);
      setMessage({ tone: "success", text: "Хадгалагдлаа" });
    } catch (err) {
      setMessage({
        tone: "error",
        text: err instanceof Error ? err.message : "Хадгалж чадсангүй",
      });
    } finally {
      setSaving(false);
    }
  }

  async function saveNistScope() {
    if (!canManageScope) {
      setMessage({
        tone: "error",
        text: "Зөвхөн удирдлага хамрах хүрээг өөрчлөх эрхтэй",
      });
      return;
    }

    setSaving(true);
    setMessage(null);
    try {
      const updates = Object.entries(nistDraft)
        .filter(([, d]) => d.scope_status !== "undecided")
        .map(([id, d]) => ({
          subcategory_id: id,
          scope_status: d.scope_status,
          exclusion_reason: d.exclusion_reason,
        }));

      const res = await fetch("/api/csf-scope", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ updates }),
      });
      const payload = await res.json().catch(() => null);
      if (!res.ok) throw new Error(getApiError(payload, "Хадгалж чадсангүй"));
      if (!payload || typeof payload !== "object" || !("rows" in payload)) {
        throw new Error("Хадгалсан мэдээлэл буруу байна");
      }
      setData((prev) => (prev ? { ...prev, rows: payload.rows } : prev));
      setMessage({ tone: "success", text: "NIST CSF scope хадгалагдлаа" });
    } catch (err) {
      setMessage({
        tone: "error",
        text: err instanceof Error ? err.message : "Хадгалж чадсангүй",
      });
    } finally {
      setSaving(false);
    }
  }

  async function finalizeScope() {
    if (!canManageScope) {
      setMessage({
        tone: "error",
        text: "Зөвхөн удирдлага хамрах хүрээг өөрчлөх эрхтэй",
      });
      return;
    }

    setSaving(true);
    setMessage(null);
    try {
      // Save selections + NIST scope together
      const updates = Object.entries(nistDraft)
        .filter(([, d]) => d.scope_status !== "undecided")
        .map(([id, d]) => ({
          subcategory_id: id,
          scope_status: d.scope_status,
          exclusion_reason: d.exclusion_reason,
        }));

      const res = await fetch("/api/csf-scope", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          updates,
          assessment_scope: {
            assessment_name:
              data?.assessment_scope.assessment_name ??
              "2026 SME Cybersecurity Risk Assessment",
            assessment_type:
              data?.assessment_scope.assessment_type ?? "Asset-based",
            selected_department_ids: Array.from(selectedDeptIds),
            selected_business_process_ids: Array.from(selectedProcessIds),
            selected_asset_ids: Array.from(selectedAssetIds),
            status: "Active",
          },
        }),
      });
      const payload = await res.json().catch(() => null);
      if (!res.ok) throw new Error(getApiError(payload, "Хадгалж чадсангүй"));
      if (!payload || typeof payload !== "object" || !("rows" in payload)) {
        throw new Error("Хадгалсан мэдээлэл буруу байна");
      }
      setData(payload);
      setMessage({ tone: "success", text: "Scope амжилттай тогтоогдлоо!" });
      setEditMode(false);
      setStep(1);
    } catch (err) {
      setMessage({
        tone: "error",
        text: err instanceof Error ? err.message : "Хадгалж чадсангүй",
      });
    } finally {
      setSaving(false);
    }
  }

  // ── Entity mutations ──────────────────────────────────────────────────────

  async function addDepartment(form: {
    department_name: string;
    owner_name: string;
    criticality: string;
    notes: string;
  }) {
    if (!canManageScope) return;

    const res = await fetch("/api/csf-scope", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ department: form }),
    });
    const payload = (await res.json().catch(() => null)) as
      | ScopeResponse
      | { error?: string }
      | null;
    if (!res.ok) throw new Error(getApiError(payload, "Хэлтэс нэмж чадсангүй"));
    if (!payload || !("departments" in payload)) {
      throw new Error("Хэлтэс нэмж чадсангүй");
    }
    setData(payload);
    // Auto-select the new department
    const newDept = payload.departments.find(
      (d) => d.department_name === form.department_name,
    );
    if (newDept) setSelectedDeptIds((prev) => new Set([...prev, newDept.id]));
  }

  async function deleteDepartment(id: number) {
    if (!canManageScope) return;

    const res = await fetch(`/api/csf-scope?department_id=${id}`, {
      method: "DELETE",
      credentials: "include",
    });
    if (!res.ok)
      throw new Error(await parseApiError(res, "Хэлтэс устгаж чадсангүй"));
    setSelectedDeptIds((prev) => {
      const s = new Set(prev);
      s.delete(id);
      return s;
    });
    await fetchData();
  }

  async function addProcess(form: {
    process_name: string;
    business_function: string;
    business_owner: string;
    criticality: string;
    description: string;
  }) {
    if (!canManageScope) return;

    const res = await fetch("/api/business-processes", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(form),
    });
    const payload = await res.json().catch(() => null);
    if (!res.ok)
      throw new Error(getApiError(payload, "Процесс нэмж чадсангүй"));
    await fetchData();
    // Auto-select the new process
    if (payload.id)
      setSelectedProcessIds((prev) => new Set([...prev, payload.id]));
  }

  async function deleteProcess(id: number) {
    if (!canManageScope) return;

    await fetch(`/api/business-processes?id=${id}`, {
      method: "DELETE",
      credentials: "include",
    });
    setSelectedProcessIds((prev) => {
      const s = new Set(prev);
      s.delete(id);
      return s;
    });
    await fetchData();
  }

  async function addAsset(form: {
    asset_name: string;
    asset_type: string;
    department: string;
    criticality: string;
    internet_exposed: boolean;
  }) {
    if (!canManageScope) return;

    const res = await fetch("/api/assets", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(form),
    });
    const payload = await res.json().catch(() => null);
    if (!res.ok)
      throw new Error(getApiError(payload, "Хөрөнгө нэмж чадсангүй"));
    await fetchData();
    if (payload.id)
      setSelectedAssetIds((prev) => new Set([...prev, payload.id]));
  }

  function toggleDept(id: number) {
    if (!canManageScope) return;

    setSelectedDeptIds((prev) => {
      const s = new Set(prev);
      if (s.has(id)) {
        s.delete(id);
      } else {
        s.add(id);
      }
      return s;
    });
  }

  function toggleProcess(id: number) {
    if (!canManageScope) return;

    setSelectedProcessIds((prev) => {
      const s = new Set(prev);
      if (s.has(id)) {
        s.delete(id);
      } else {
        s.add(id);
      }
      return s;
    });
  }

  function syncNistScopeFromAssets(nextSelectedAssetIds: Set<number>) {
    if (!data || !canManageScope) return;

    const nextAutoIds = deriveAssetScopedSubcategoryIds(
      data.rows,
      data.assets,
      nextSelectedAssetIds,
    );

    setNistDraft((prev) => {
      const recalculated = recalculateAssetDerivedDraft(
        data.rows,
        prev,
        autoScopedIds,
        nextAutoIds,
      );
      return recalculated.draft;
    });
    setAutoScopedIds(nextAutoIds);
  }

  function toggleAsset(id: number) {
    if (!canManageScope) return;

    const next = new Set(selectedAssetIds);
    if (next.has(id)) {
      next.delete(id);
    } else {
      next.add(id);
    }
    setSelectedAssetIds(next);
    syncNistScopeFromAssets(next);
  }

  async function saveSelectionsForAssetIds(assetIds: Set<number>) {
    if (!data || !canManageScope) return;
    try {
      const res = await fetch("/api/csf-scope", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          assessment_scope: {
            assessment_name:
              data.assessment_scope.assessment_name ??
              "2026 SME Cybersecurity Risk Assessment",
            assessment_type:
              data.assessment_scope.assessment_type ?? "Asset-based",
            selected_department_ids: Array.from(selectedDeptIds),
            selected_business_process_ids: Array.from(selectedProcessIds),
            selected_asset_ids: Array.from(assetIds),
            status:
              data.assessment_scope.status === "Active" ? "Active" : "Draft",
          },
        }),
      });
      if (!res.ok) return;
      const payload = (await res.json()) as ScopeResponse;
      setData((prev) =>
        prev
          ? {
              ...prev,
              assessment_scope: payload.assessment_scope,
              scope_summary: payload.scope_summary,
            }
          : prev,
      );
    } catch {
      // The normal step save/finalize flow still persists the latest selection.
    }
  }

  useEffect(() => {
    if (!data || loading) return;
    const timeout = window.setTimeout(() => {
      void saveSelectionsForAssetIds(selectedAssetIds);
    }, 500);
    return () => window.clearTimeout(timeout);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedAssetIds]);

  function onNistChange(id: string, status: ScopeStatus, reason?: string) {
    if (!canManageScope) return;

    if (status === "out_of_scope" || status === "undecided") {
      setAutoScopedIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
    setNistDraft((prev) => ({
      ...prev,
      [id]: {
        scope_status: status,
        exclusion_reason:
          reason !== undefined ? reason : (prev[id]?.exclusion_reason ?? ""),
      },
    }));
  }

  /** Auto-select NIST CSF subcategories based on the currently selected assets. */
  function applyAutoSelection() {
    if (!data || !canManageScope) return;

    const nextAutoIds = deriveAssetScopedSubcategoryIds(
      data.rows,
      data.assets,
      selectedAssetIds,
    );

    setNistDraft((prev) => {
      const recalculated = recalculateAssetDerivedDraft(
        data.rows,
        prev,
        autoScopedIds,
        nextAutoIds,
      );
      return recalculated.draft;
    });
    setAutoScopedIds(nextAutoIds);
  }

  async function handleNext() {
    if (!canManageScope) {
      if (step < 5) setStep(step + 1);
      return;
    }

    if (step === 1 || step === 2 || step === 3) {
      if (step === 3) {
        applyAutoSelection();
      }
      await saveSelections();
    } else if (step === 4) {
      await saveNistScope();
    }
    if (step < 5) setStep(step + 1);
  }

  function handlePrev() {
    setMessage(null);
    setStep((s) => Math.max(1, s - 1));
  }

  // ── Render ────────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="flex h-96 items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-slate-200 border-t-slate-700" />
      </div>
    );
  }

  if (!data) {
    return (
      <div className="flex h-96 flex-col items-center justify-center gap-3">
        <AlertTriangle className="h-10 w-10 text-rose-500" />
        <p className="text-sm text-muted-foreground">
          Мэдээлэл уншиж чадсангүй
        </p>
        <Button size="sm" onClick={fetchData}>
          Дахин оролдох
        </Button>
      </div>
    );
  }

  // ── Saved Scope View ───────────────────────────────────────────────────────
  const isFinalized = data.assessment_scope?.status === "Active";
  const showSavedScopeView = !canManageScope || (isFinalized && !editMode);

  if (showSavedScopeView) {
    const savedDepts = data.departments.filter((d) =>
      (data.assessment_scope.selected_department_ids ?? [])
        .map(Number)
        .includes(d.id),
    );
    const savedProcs = data.business_processes.filter((p) =>
      (data.assessment_scope.selected_business_process_ids ?? [])
        .map(Number)
        .includes(p.id),
    );
    const savedAssets = data.assets.filter((a) =>
      (data.assessment_scope.selected_asset_ids ?? [])
        .map(Number)
        .includes(a.id),
    );
    const inScopeCount = data.rows.filter(
      (r) => r.scope_status === "in_scope",
    ).length;
    const csfCoveragePct = data.rows.length
      ? Math.round((inScopeCount / data.rows.length) * 100)
      : 0;

    const tiles = [
      {
        label: "Хэлтэс",
        value: savedDepts.length,
        total: data.departments.length,
        sub: "Хамрагдсан хэлтэс",
        color: "text-violet-600 dark:!text-violet-500",
        bg: "bg-violet-50 border-violet-200 dark:bg-slate-800 dark:border-slate-700",
        icon: Building2,
      },
      {
        label: "Процесс",
        value: savedProcs.length,
        total: data.business_processes.length,
        sub: "Бизнес процесс",
        color: "text-sky-600 dark:!text-sky-500",
        bg: "bg-sky-50 border-sky-200 dark:bg-slate-800 dark:border-slate-700",
        icon: Database,
      },
      {
        label: "Хөрөнгө",
        value: savedAssets.length,
        total: data.assets.length,
        sub: "Мэдээллийн хөрөнгө",
        color: "text-emerald-600 dark:!text-emerald-500",
        bg: "bg-emerald-50 border-emerald-200 dark:bg-slate-800 dark:border-slate-700",
        icon: ShieldCheck,
      },
      {
        label: "NIST CSF дэд ангилал",
        value: inScopeCount,
        total: data.rows.length,
        sub: `${csfCoveragePct}% хамрах хүрээ`,
        color: "text-orange-600 dark:!text-orange-500",
        bg: "bg-orange-50 border-orange-200 dark:bg-slate-800 dark:border-slate-700",
        icon: CheckCircle2,
      },
    ];

    return (
      <div className="app-page p-4 pb-8 sm:p-6 md:p-8">
        <div className="mx-auto max-w-7xl space-y-6">
          {/* Header */}
          <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div>
              <h1 className="mb-2 text-3xl font-bold sm:text-4xl">
                Эрсдэлийн үнэлгээний хамрах хүрээ
              </h1>
            </div>
            <div className="flex shrink-0 flex-wrap items-center justify-end gap-2">
              <span className="flex items-center gap-1.5 rounded-full border border-emerald-300 bg-emerald-50 px-3 py-1 text-xs font-semibold text-emerald-700 dark:border-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-300">
                <CheckCircle2 className="h-3.5 w-3.5" />
                {isFinalized ? "Идэвхтэй" : "Хадгалсан"}
              </span>
              {canManageScope && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    setEditMode(true);
                    setStep(1);
                    setMessage(null);
                  }}
                >
                  Өөрчлөх
                </Button>
              )}
            </div>
          </div>

          {/* Tiles */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
            {tiles.map((tile) => {
              const Icon = tile.icon;
              return (
                <div
                  key={tile.label}
                  className={`rounded-xl border p-4 shadow-sm dark:shadow-none ${tile.bg}`}
                >
                  <Icon className={`mb-2 h-4 w-4 ${tile.color}`} />
                  <div className={`text-2xl font-bold ${tile.color}`}>
                    {tile.value}
                  </div>
                  <div className="mt-0.5 flex items-center gap-1 text-sm font-semibold text-slate-900 dark:text-white!">
                    <span>{tile.label}</span>
                    <span className="text-xs font-medium text-slate-500 dark:text-slate-300">
                      / {tile.total}
                    </span>
                  </div>
                  <div className="mt-0.5 text-xs text-slate-600 dark:text-white!">
                    {tile.sub}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Detail panels */}
          <div className="grid gap-4 sm:grid-cols-2">
            {/* Departments */}
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-950">
              <div className="mb-3 flex items-center justify-between gap-3">
                <h3 className="flex items-center gap-2 text-sm font-semibold">
                  <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-violet-50 text-violet-600 dark:bg-violet-950/40 dark:text-violet-300">
                    <Building2 className="h-4 w-4" />
                  </span>
                  Хэлтэсүүд
                </h3>
                <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                  {savedDepts.length}
                </span>
              </div>
              {savedDepts.length === 0 ? (
                <p className="rounded-lg border border-dashed border-slate-200 p-4 text-center text-xs text-muted-foreground dark:border-slate-800">
                  Хэлтэс сонгоогүй
                </p>
              ) : (
                <div className="space-y-2">
                  {savedDepts.map((d) => (
                    <div
                      key={d.id}
                      className="flex items-center justify-between gap-3 rounded-lg border border-slate-100 bg-slate-50 px-3 py-2 text-sm dark:border-slate-800 dark:bg-slate-900/60"
                    >
                      <span className="flex min-w-0 items-center gap-2">
                        <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-500" />
                        <span className="truncate font-medium">
                          {d.department_name}
                        </span>
                      </span>
                      <span className="shrink-0 text-xs text-muted-foreground">
                        {d.asset_count} хөрөнгө
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Processes */}
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-950">
              <div className="mb-3 flex items-center justify-between gap-3">
                <h3 className="flex items-center gap-2 text-sm font-semibold">
                  <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-50 text-sky-600 dark:bg-sky-950/40 dark:text-sky-300">
                    <Database className="h-4 w-4" />
                  </span>
                  Бизнесийн процессууд
                </h3>
                <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                  {savedProcs.length}
                </span>
              </div>
              {savedProcs.length === 0 ? (
                <p className="rounded-lg border border-dashed border-slate-200 p-4 text-center text-xs text-muted-foreground dark:border-slate-800">
                  Процесс сонгоогүй
                </p>
              ) : (
                <div className="max-h-64 space-y-2 overflow-y-auto pr-1">
                  {savedProcs.map((p) => (
                    <div
                      key={p.id}
                      className="flex items-center justify-between gap-3 rounded-lg border border-slate-100 bg-slate-50 px-3 py-2 text-sm dark:border-slate-800 dark:bg-slate-900/60"
                    >
                      <span className="flex min-w-0 items-center gap-2">
                        <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-500" />
                        <span className="truncate font-medium">
                          {p.process_name}
                        </span>
                      </span>
                      {p.criticality && (
                        <span
                          className={`ml-2 shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-semibold ${CRITICALITY_COLORS[p.criticality] ?? CRITICALITY_COLORS.Low}`}
                        >
                          {p.criticality}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Assets */}
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-950">
              <div className="mb-3 flex items-center justify-between gap-3">
                <h3 className="flex items-center gap-2 text-sm font-semibold">
                  <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-50 text-emerald-600 dark:bg-emerald-950/40 dark:text-emerald-300">
                    <ShieldCheck className="h-4 w-4" />
                  </span>
                  Хамрагдах хөрөнгүүд
                </h3>
                <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                  {savedAssets.length}
                </span>
              </div>
              {savedAssets.length === 0 ? (
                <p className="rounded-lg border border-dashed border-slate-200 p-4 text-center text-xs text-muted-foreground dark:border-slate-800">
                  Хөрөнгө сонгоогүй
                </p>
              ) : (
                <div className="max-h-64 space-y-2 overflow-y-auto pr-1">
                  {savedAssets.map((a) => (
                    <div
                      key={a.id}
                      className="flex items-center justify-between gap-3 rounded-lg border border-slate-100 bg-slate-50 px-3 py-2 text-sm dark:border-slate-800 dark:bg-slate-900/60"
                    >
                      <div className="flex min-w-0 items-center gap-2">
                        <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-500" />
                        <span className="truncate font-medium">
                          {a.asset_name}
                        </span>
                      </div>
                      {a.asset_type && (
                        <span className="ml-2 shrink-0 rounded-md bg-white px-2 py-0.5 text-[10px] text-muted-foreground ring-1 ring-slate-200 dark:bg-slate-950 dark:ring-slate-800">
                          {a.asset_type}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* NIST CSF functions */}
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-950">
              <div className="mb-3 flex items-center justify-between gap-3">
                <h3 className="flex items-center gap-2 text-sm font-semibold">
                  <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-orange-50 text-orange-600 dark:bg-orange-950/40 dark:text-orange-300">
                    <CheckCircle2 className="h-4 w-4" />
                  </span>
                  NIST CSF дэд ангилалууд
                </h3>
                <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                  {inScopeCount}/{data.rows.length}
                </span>
              </div>
              <div className="space-y-3">
                {FUNCTION_ORDER.map((fc) => {
                  const meta = FUNCTION_META[fc];
                  const total = data.rows.filter(
                    (r) => r.function_code === fc,
                  ).length;
                  const inScope = data.rows.filter(
                    (r) =>
                      r.function_code === fc && r.scope_status === "in_scope",
                  ).length;
                  const pct =
                    total > 0 ? Math.round((inScope / total) * 100) : 0;
                  const Icon = meta.icon;
                  return (
                    <div
                      key={fc}
                      className="rounded-lg border border-slate-100 bg-slate-50 px-3 py-2 dark:border-slate-800 dark:bg-slate-900/60"
                    >
                      <div className="flex items-center gap-3">
                        <div
                          className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${meta.bg}`}
                        >
                          <Icon className="h-4 w-4 text-white" />
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center justify-between gap-3 text-xs">
                            <span
                              className={`${meta.color} truncate font-semibold`}
                            >
                              {fc} — {meta.mn}
                            </span>
                            <span className="shrink-0 text-muted-foreground">
                              {inScope}/{total}
                            </span>
                          </div>
                          <div className="mt-2 flex items-center gap-2">
                            <div className="h-2 flex-1 rounded-full bg-slate-100 dark:bg-slate-800">
                              <div
                                className={`h-2 rounded-full ${meta.bg}`}
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                            <span className="w-8 text-right text-[11px] font-semibold text-muted-foreground">
                              {pct}%
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-4 sm:p-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight">
          Эрсдэлийн үнэлгээний хамрах хүрээ
        </h1>
      </div>

      {/* Step indicator */}
      <div className="rounded-xl border bg-white p-3 shadow-sm dark:bg-slate-950">
        <StepIndicator current={step} onNavigate={setStep} />
      </div>

      {!canManageScope && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm font-medium text-amber-800 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-200">
          Зөвхөн удирдлага эрсдэлийн үнэлгээний хамрах хүрээг өөрчлөх эрхтэй.
        </div>
      )}

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
          <Step1Departments
            departments={data.departments}
            selected={selectedDeptIds}
            onToggle={toggleDept}
            onAdd={addDepartment}
            onDelete={deleteDepartment}
            canEdit={canManageScope}
          />
        )}
        {step === 2 && (
          <Step2Processes
            processes={data.business_processes}
            selected={selectedProcessIds}
            onToggle={toggleProcess}
            onAdd={addProcess}
            onDelete={deleteProcess}
            departments={data.departments}
            selectedDeptIds={selectedDeptIds}
            canEdit={canManageScope}
          />
        )}
        {step === 3 && (
          <Step3Assets
            assets={data.assets}
            selected={selectedAssetIds}
            onToggle={toggleAsset}
            onAdd={addAsset}
            departments={data.departments}
            selectedDeptIds={selectedDeptIds}
            canEdit={canManageScope}
          />
        )}
        {step === 4 && (
          <Step4NistCsf
            rows={data.rows}
            draft={nistDraft}
            onChange={onNistChange}
            canEdit={canManageScope}
          />
        )}
        {step === 5 && (
          <Step5Review
            departments={data.departments}
            selectedDeptIds={selectedDeptIds}
            processes={data.business_processes}
            selectedProcessIds={selectedProcessIds}
            assets={data.assets}
            selectedAssetIds={selectedAssetIds}
            rows={data.rows}
            draft={nistDraft}
          />
        )}
      </div>

      {/* Navigation */}
      <div className="flex items-center justify-between">
        <Button
          variant="outline"
          onClick={handlePrev}
          disabled={step === 1 || saving}
        >
          ← Өмнөх
        </Button>
        <span className="text-xs text-muted-foreground">
          {step} / {STEPS.length}
        </span>
        {step < 5 ? (
          <Button onClick={handleNext} disabled={saving}>
            {saving ? "Хадгалж байна…" : canManageScope ? "Дараах →" : "Дараах"}
          </Button>
        ) : canManageScope ? (
          <Button
            onClick={finalizeScope}
            disabled={saving}
            className="bg-emerald-600 hover:bg-emerald-700 text-white"
          >
            {saving ? "Хадгалж байна…" : "Хадгалах ✓"}
          </Button>
        ) : (
          <Button disabled variant="outline">
            Зөвхөн удирдлага
          </Button>
        )}
      </div>
    </div>
  );
}
