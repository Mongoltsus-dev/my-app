"use client";

import {
  NIST_FUNCTION_LABELS,
  NIST_FUNCTION_ORDER,
  RISK_LEVEL_COLORS,
  RISK_LEVEL_LABELS,
  nistFunctionCode,
  nistFunctionLabel,
  normalizedScoreValue,
  riskOwnerLabel,
} from "@/lib/risk-display";
import { riskLevelFromScore } from "@/lib/risk-scoring";
import {
  AlertTriangle,
  Database,
  Filter,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

// ─── Types ────────────────────────────────────────────────────────────────────

type Treatment = "Accept" | "Mitigate" | "Transfer" | null;
type HeatMapSelection = { likelihood: number; impact: number } | null;

interface RiskRow {
  id: number;
  risk_id: string;
  risk_title: string;
  risk_description: string | null;
  asset_id: number | null;
  asset_name: string | null;
  asset_type: string | null;
  criticality: string | null;
  threat_name: string | null;
  threat_category: string | null;
  nist_csf_function: string | null;
  nist_csf_category: string | null;
  inherent_likelihood: number | string | null;
  inherent_impact: number | string | null;
  inherent_risk_score: number | null;
  inherent_risk_level: string | null;
  residual_risk_score: number | null;
  residual_risk_level: string | null;
  risk_treatment: string | null;
  risk_treatment_approval_status?: string | null;
  risk_treatment_approved_by?: string | null;
  risk_treatment_approved_at?: string | null;
  treatment_rationale: string | null;
  risk_owner: string | null;
  department_control_owner?: string | null;
  treatment_owner?: string | null;
  assessed_by?: string | null;
  status: string | null;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const ALL = "Бүгд";

const RISK_LEVEL_ACCENT: Record<string, string> = {
  Critical: "bg-red-500",
  High: "bg-orange-500",
  Medium: "bg-amber-500",
  Low: "bg-emerald-500",
};

const NIST_COLORS: Record<string, string> = {
  GV: "bg-violet-100 text-violet-700 dark:bg-violet-950/50 dark:text-violet-300",
  ID: "bg-blue-100 text-blue-700 dark:bg-blue-950/50 dark:text-blue-300",
  PR: "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-300",
  DE: "bg-amber-100 text-amber-700 dark:bg-amber-950/50 dark:text-amber-300",
  RS: "bg-orange-100 text-orange-700 dark:bg-orange-950/50 dark:text-orange-300",
  RC: "bg-pink-100 text-pink-700 dark:bg-pink-950/50 dark:text-pink-300",
};

const HEAT_MAP_LIKELIHOOD = [
  { value: 1, label: "Маш бага" },
  { value: 2, label: "Бага" },
  { value: 3, label: "Дунд" },
  { value: 4, label: "Их" },
  { value: 5, label: "Маш их" },
];

const HEAT_MAP_IMPACT = [
  { value: 5, label: "Маш их" },
  { value: 4, label: "Их" },
  { value: 3, label: "Дунд" },
  { value: 2, label: "Бага" },
  { value: 1, label: "Маш бага" },
];

const HEAT_MAP_LIKELIHOOD_ROWS = [...HEAT_MAP_LIKELIHOOD].reverse();
const HEAT_MAP_IMPACT_COLUMNS = [...HEAT_MAP_IMPACT].reverse();

const TREATMENT_LABELS: Record<
  string,
  { pending: string; approved: string; color: string; doneColor: string }
> = {
  Mitigate: {
    pending: "Бууруулж байна",
    approved: "Бууруулсан",
    color:
      "border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-900/60 dark:bg-blue-950/40 dark:text-blue-300",
    doneColor:
      "border-blue-300 bg-blue-100 text-blue-800 dark:border-blue-700/60 dark:bg-blue-900/40 dark:text-blue-200",
  },
  Transfer: {
    pending: "Шилжүүлж байна",
    approved: "Шилжүүлсэн",
    color:
      "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900/60 dark:bg-amber-950/40 dark:text-amber-300",
    doneColor:
      "border-amber-300 bg-amber-100 text-amber-800 dark:border-amber-700/60 dark:bg-amber-900/40 dark:text-amber-200",
  },
  Accept: {
    pending: "Хүлээж авч байна",
    approved: "Хүлээж авсан",
    color:
      "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900/60 dark:bg-emerald-950/40 dark:text-emerald-300",
    doneColor:
      "border-emerald-300 bg-emerald-100 text-emerald-800 dark:border-emerald-700/60 dark:bg-emerald-900/40 dark:text-emerald-200",
  },
  Avoid: {
    pending: "Зайлсхийж байна",
    approved: "Зайлсхийсэн",
    color:
      "border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-900/60 dark:bg-rose-950/40 dark:text-rose-300",
    doneColor:
      "border-rose-300 bg-rose-100 text-rose-800 dark:border-rose-700/60 dark:bg-rose-900/40 dark:text-rose-200",
  },
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

const riskLevelColor = (level: string | null | undefined) =>
  RISK_LEVEL_COLORS[level ?? ""] ?? RISK_LEVEL_COLORS.Low;

const riskLevelAccent = (level: string | null | undefined) =>
  RISK_LEVEL_ACCENT[level ?? ""] ?? "bg-slate-400";

const riskLevelLabel = (level: string | null | undefined) =>
  RISK_LEVEL_LABELS[level ?? ""] ?? level ?? "—";

const nistCategoryCode = (
  category: string | null | undefined,
  fallback?: string | null,
) => {
  const rawCategory = (category || "").trim();
  if (rawCategory) return rawCategory;

  const rawFallback = (fallback || "").trim();
  const prefix = rawFallback.split(/[.\s-]/)[0].toUpperCase();
  if (rawFallback.includes(".") && NIST_FUNCTION_LABELS[prefix]) {
    return rawFallback.toUpperCase();
  }

  return "";
};

const riskWeight = (level: string | null | undefined) => {
  switch (level) {
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

const riskLikelihood = (risk: RiskRow) =>
  normalizedScoreValue(risk.inherent_likelihood);

const riskImpact = (risk: RiskRow) =>
  normalizedScoreValue(risk.inherent_impact);

const heatMapLevel = riskLevelFromScore;

const heatMapCellColor = (score: number, selected: boolean) => {
  const level = heatMapLevel(score);
  const selectedRing = selected
    ? "ring-2 ring-blue-600 ring-offset-2 dark:ring-blue-300"
    : "";
  const colors: Record<string, string> = {
    Low: "border-emerald-300 bg-emerald-100 text-emerald-900 hover:bg-emerald-200 dark:border-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-200",
    Medium:
      "border-amber-300 bg-amber-100 text-amber-900 hover:bg-amber-200 dark:border-amber-800 dark:bg-amber-950/60 dark:text-amber-200",
    High: "border-orange-300 bg-orange-100 text-orange-900 hover:bg-orange-200 dark:border-orange-800 dark:bg-orange-950/60 dark:text-orange-200",
    Critical:
      "border-red-300 bg-red-100 text-red-900 hover:bg-red-200 dark:border-red-800 dark:bg-red-950/60 dark:text-red-200",
  };
  return `${colors[level]} ${selectedRing}`;
};

const heatMapKey = (likelihood: number, impact: number) =>
  `${likelihood}-${impact}`;

// ─── Page ────────────────────────────────────────────────────────────────────

export default function RisksPage() {
  const [risks, setRisks] = useState<RiskRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [search, setSearch] = useState("");
  const [filterLevel, setFilterLevel] = useState(ALL);
  const [filterFunction, setFilterFunction] = useState(ALL);
  const [filterTreatment, setFilterTreatment] = useState(ALL);
  const [heatMapSelection, setHeatMapSelection] =
    useState<HeatMapSelection>(null);

  // ── Fetch ──────────────────────────────────────────────────────
  useEffect(() => {
    let mounted = true;
    fetch("/api/risk-register")
      .then(async (riskRes) => {
        if (!riskRes.ok) throw new Error("Failed to fetch");
        const riskData = await riskRes.json();
        if (!mounted) return [];
        const nextRisks = (riskData.risks ?? []) as RiskRow[];
        setRisks(nextRisks);
        setError("");
      })
      .catch(() => {
        if (!mounted) return;
        setError("Эрсдэлийн мэдээлэл ачаалах үед алдаа гарлаа.");
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, []);

  // ── Stats ──────────────────────────────────────────────────────
  const stats = useMemo(() => {
    const treated = risks.filter((r) => r.risk_treatment != null).length;
    const untreated = risks.filter((r) => r.risk_treatment == null).length;
    const critical = risks.filter(
      (r) => r.inherent_risk_level === "Critical",
    ).length;
    const high = risks.filter((r) => r.inherent_risk_level === "High").length;
    return { total: risks.length, treated, untreated, critical, high };
  }, [risks]);

  // ── Filtered list ──────────────────────────────────────────────
  const filteredBeforeHeatMap = useMemo(() => {
    const q = search.trim().toLowerCase();
    return risks
      .filter((r) => {
        if (filterLevel !== ALL && r.inherent_risk_level !== filterLevel)
          return false;
        if (
          filterFunction !== ALL &&
          nistFunctionCode(r.nist_csf_function, r.nist_csf_category) !==
            filterFunction
        )
          return false;
        if (filterTreatment === "untreated" && r.risk_treatment != null)
          return false;
        if (
          filterTreatment !== ALL &&
          filterTreatment !== "untreated" &&
          r.risk_treatment !== filterTreatment
        )
          return false;
        if (q) {
          const hay = [
            r.risk_title,
            r.risk_id,
            r.asset_name,
            r.threat_name,
            r.nist_csf_function,
            r.nist_csf_category,
            nistFunctionLabel(
              nistFunctionCode(r.nist_csf_function, r.nist_csf_category),
            ),
            r.risk_owner,
          ]
            .filter(Boolean)
            .join(" ")
            .toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      })
      .sort(
        (a, b) =>
          riskWeight(b.inherent_risk_level) - riskWeight(a.inherent_risk_level),
      );
  }, [risks, filterLevel, filterFunction, filterTreatment, search]);

  const heatMapCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const risk of filteredBeforeHeatMap) {
      const likelihood = riskLikelihood(risk);
      const impact = riskImpact(risk);
      if (!likelihood || !impact) continue;
      const key = heatMapKey(likelihood, impact);
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return counts;
  }, [filteredBeforeHeatMap]);

  const filtered = useMemo(() => {
    if (!heatMapSelection) return filteredBeforeHeatMap;
    return filteredBeforeHeatMap.filter(
      (risk) =>
        riskLikelihood(risk) === heatMapSelection.likelihood &&
        riskImpact(risk) === heatMapSelection.impact,
    );
  }, [filteredBeforeHeatMap, heatMapSelection]);

  const hasActiveFilters =
    search.trim() !== "" ||
    filterLevel !== ALL ||
    filterFunction !== ALL ||
    filterTreatment !== ALL ||
    heatMapSelection !== null;

  const resetFilters = () => {
    setSearch("");
    setFilterLevel(ALL);
    setFilterFunction(ALL);
    setFilterTreatment(ALL);
    setHeatMapSelection(null);
  };

  // ─── Render ───────────────────────────────────────────────────────────────

  return (
    <div className="app-page p-4 pb-8 sm:p-6 md:p-8">
      <div className="mx-auto max-w-375 space-y-5">
        <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">
          Эрсдэлийн бүртгэл
        </h1>

        {!loading && (
          <section
            className={`grid gap-4 ${
              !error && risks.length > 0
                ? "xl:grid-cols-[minmax(0,1fr)_360px]"
                : ""
            }`}
          >
            {!error && risks.length > 0 && (
              <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-950">
                <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                  <div>
                    <h2 className="text-base font-bold">
                      Эрсдэлийн дулааны матриц
                    </h2>
                  </div>
                  <div>
                    {heatMapSelection && (
                      <button
                        type="button"
                        onClick={() => setHeatMapSelection(null)}
                        className="inline-flex h-8 items-center justify-center rounded-md border border-border px-3 text-xs font-semibold text-muted-foreground transition hover:bg-accent hover:text-accent-foreground"
                      >
                        Матрицын шүүлтүүр арилгах
                      </button>
                    )}
                  </div>
                </div>

                <div className="overflow-x-auto">
                  <div className="mx-auto w-fit min-w-155 rounded-xl border border-slate-200 bg-slate-50/70 p-3 shadow-inner dark:border-slate-800 dark:bg-slate-900/30">
                    <div className="grid grid-cols-[28px_88px_repeat(5,82px)] gap-1.5">
                      <div />
                      <div />
                      <div className="col-span-5 rounded-md border border-slate-200 bg-white py-1 text-center text-xs font-bold text-slate-700 shadow-sm dark:border-slate-800 dark:bg-slate-950 dark:text-slate-200">
                        Нөлөөлөл
                      </div>
                      <div />
                      <div />
                      {HEAT_MAP_IMPACT_COLUMNS.map((item) => (
                        <div
                          key={item.value}
                          className="rounded-md border border-slate-200 bg-white px-1.5 py-1.5 text-center shadow-sm dark:border-slate-800 dark:bg-slate-950"
                        >
                          <p className="text-[11px] font-semibold leading-tight">
                            {item.label}
                          </p>
                          <p className="text-[11px] text-muted-foreground">
                            {item.value}
                          </p>
                        </div>
                      ))}

                      {HEAT_MAP_LIKELIHOOD_ROWS.map(
                        (likelihoodItem, likelihoodIndex) => (
                          <div key={likelihoodItem.value} className="contents">
                            {likelihoodIndex === 0 && (
                              <div className="row-span-5 flex items-center justify-center rounded-md border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
                                <span className="rotate-180 text-xs font-bold text-slate-700 dark:text-slate-200 [writing-mode:vertical-rl]">
                                  Магадлал
                                </span>
                              </div>
                            )}
                            <div className="flex min-h-13 items-center justify-end rounded-md border border-slate-200 bg-white px-2 text-right shadow-sm dark:border-slate-800 dark:bg-slate-950">
                              <div>
                                <p className="text-[11px] font-semibold leading-tight">
                                  {likelihoodItem.label}
                                </p>
                                <p className="text-[11px] text-muted-foreground">
                                  {likelihoodItem.value}
                                </p>
                              </div>
                            </div>
                            {HEAT_MAP_IMPACT_COLUMNS.map((impactItem) => {
                              const score =
                                likelihoodItem.value * impactItem.value;
                              const key = heatMapKey(
                                likelihoodItem.value,
                                impactItem.value,
                              );
                              const count = heatMapCounts.get(key) ?? 0;
                              const selected =
                                heatMapSelection?.likelihood ===
                                  likelihoodItem.value &&
                                heatMapSelection?.impact === impactItem.value;
                              return (
                                <button
                                  key={key}
                                  type="button"
                                  onClick={() =>
                                    setHeatMapSelection((prev) =>
                                      prev?.likelihood ===
                                        likelihoodItem.value &&
                                      prev?.impact === impactItem.value
                                        ? null
                                        : {
                                            likelihood: likelihoodItem.value,
                                            impact: impactItem.value,
                                          },
                                    )
                                  }
                                  className={`min-h-13 rounded-md border px-2 py-2 text-center shadow-sm transition-all hover:-translate-y-0.5 hover:shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${heatMapCellColor(score, selected)}`}
                                >
                                  <p className="text-lg font-black leading-none">
                                    {score}
                                  </p>
                                  <p
                                    className={`mx-auto mt-1 w-fit rounded-full px-1.5 py-0.5 text-[10px] font-bold ${
                                      count > 0
                                        ? "bg-white/80 text-current shadow-sm dark:bg-slate-950/60"
                                        : "text-current opacity-70"
                                    }`}
                                  >
                                    {count} эрсдэл
                                  </p>
                                </button>
                              );
                            })}
                          </div>
                        ),
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}

            <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-950">
              <div className="mb-3 flex items-center justify-between">
                <div>
                  <h2 className="text-base font-bold">Ерөнхий төлөв</h2>
                  <p className="mt-1 text-xs text-muted-foreground">
                    Бүртгэлийн богино хураангуй
                  </p>
                </div>
                <ShieldCheck className="size-5 text-blue-600" />
              </div>
              <div className="grid grid-cols-2 gap-3 xl:grid-cols-1">
                {[
                  {
                    label: "Нийт эрсдэл",
                    value: stats.total,
                    icon: ShieldAlert,
                    color: "text-blue-700 dark:text-blue-300",
                    surface:
                      "border-blue-200 bg-blue-50 dark:border-blue-900/60 dark:bg-blue-950/30",
                  },
                  {
                    label: "Ноцтой / Өндөр",
                    value: stats.critical + stats.high,
                    icon: AlertTriangle,
                    color: "text-red-700 dark:text-red-300",
                    surface:
                      "border-red-200 bg-red-50 dark:border-red-900/60 dark:bg-red-950/30",
                  },
                  {
                    label: "Арга хэмжээ авсан",
                    value: stats.treated,
                    icon: ShieldCheck,
                    color: "text-emerald-700 dark:text-emerald-300",
                    surface:
                      "border-emerald-200 bg-emerald-50 dark:border-emerald-900/60 dark:bg-emerald-950/30",
                  },
                  {
                    label: "Хүлээгдэж буй",
                    value: stats.untreated,
                    icon: Database,
                    color: "text-amber-700 dark:text-amber-300",
                    surface:
                      "border-amber-200 bg-amber-50 dark:border-amber-900/60 dark:bg-amber-950/30",
                  },
                ].map(({ label, value, icon: Icon, color, surface }) => (
                  <div
                    key={label}
                    className={`rounded-xl border p-3 ${surface}`}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-xs font-semibold uppercase text-muted-foreground">
                        {label}
                      </span>
                      <Icon className={`size-4 ${color}`} />
                    </div>
                    <div className={`mt-2 text-2xl font-bold ${color}`}>
                      {value}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </section>
        )}

        {/* Filters */}
        <section className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-950">
          <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 className="text-base font-bold">Эрсдэлийн бүртгэл</h2>
              <p className="mt-1 text-xs text-muted-foreground">
                Хайлт болон шүүлтүүрээр хэрэгтэй эрсдэлээ хурдан олно.
              </p>
            </div>
            <span className="w-fit rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold text-slate-700 dark:bg-slate-900 dark:text-slate-200">
              {filtered.length} эрсдэл харагдаж байна
            </span>
          </div>
          <div className="flex flex-col gap-3 lg:flex-row">
            <div className="relative min-w-0 flex-1">
              <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <input
                type="text"
                placeholder="Эрсдэл, хөрөнгө, аюул, NIST хайх..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="app-form-field h-10 w-full rounded-md border pl-9 pr-4 text-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
              />
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 lg:flex lg:shrink-0">
              <label className="relative">
                <Filter className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                <select
                  value={filterLevel}
                  onChange={(e) => setFilterLevel(e.target.value)}
                  className="app-form-field h-10 w-full rounded-md border pl-9 pr-8 text-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 sm:w-40"
                >
                  <option value={ALL}>Бүх түвшин</option>
                  {["Critical", "High", "Medium", "Low"].map((v) => (
                    <option key={v} value={v}>
                      {riskLevelLabel(v)}
                    </option>
                  ))}
                </select>
              </label>
              <select
                value={filterFunction}
                onChange={(e) => setFilterFunction(e.target.value)}
                className="app-form-field h-10 w-full rounded-md border px-3 text-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 sm:w-44"
              >
                <option value={ALL}>Бүх функц</option>
                {NIST_FUNCTION_ORDER.map((code) => (
                  <option key={code} value={code}>
                    {nistFunctionLabel(code)} ({code})
                  </option>
                ))}
              </select>
              <select
                value={filterTreatment}
                onChange={(e) => setFilterTreatment(e.target.value)}
                className="app-form-field h-10 w-full rounded-md border px-3 text-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 sm:w-48"
              >
                <option value={ALL}>Бүх арга хэмжээ</option>
                <option value="untreated">Хүлээгдэж буй</option>
                <option value="Accept">Хүлээж авсан</option>
                <option value="Mitigate">Бууруулсан</option>
                <option value="Transfer">Шилжүүлсэн</option>
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
        </section>

        {/* Risk selection and details */}
        {loading ? (
          <div className="h-130 animate-pulse rounded-lg border border-border bg-muted/40" />
        ) : error ? (
          <div className="flex min-h-64 flex-col items-center justify-center rounded-lg border border-border bg-card px-4 text-center text-muted-foreground">
            <AlertTriangle className="mb-3 size-10 text-orange-500" />
            <p className="text-sm">{error}</p>
          </div>
        ) : risks.length === 0 ? (
          <div className="flex min-h-64 flex-col items-center justify-center rounded-lg border border-border bg-card px-4 text-center">
            <ShieldAlert className="mb-3 size-10 text-muted-foreground" />
            <p className="text-sm font-medium">
              Эрсдэлийн бүртгэл хоосон байна.
            </p>
            <p className="mt-1 text-sm text-muted-foreground">
              Эрсдэлийн үнэлгээ хэсгийг ашиглан эрсдэлүүдийг нэмнэ үү.
            </p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex min-h-48 flex-col items-center justify-center rounded-lg border border-border bg-card px-4 text-center text-muted-foreground">
            <AlertTriangle className="mb-3 size-8 opacity-40" />
            <p className="text-sm">Шүүлтүүрт тохирох эрсдэл олдсонгүй.</p>
          </div>
        ) : (
          <div className="grid gap-4 lg:grid-cols-1">
            <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
              <div className="border-b border-slate-200 px-4 py-3 dark:border-slate-800">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <h2 className="text-sm font-bold">Бүртгэлийн хүснэгт</h2>
                    <p className="mt-0.5 text-xs text-muted-foreground">
                      Дэлгэрэнгүй мэдээлэл болон арга хэмжээг харахын тулд
                      эрсдэлээ сонгоно уу.
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    {heatMapSelection && (
                      <span className="rounded-full bg-blue-50 px-2.5 py-1 text-xs font-semibold text-blue-700 dark:bg-blue-950/40 dark:text-blue-300">
                        Матрицаар шүүсэн
                      </span>
                    )}
                    <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-700 dark:bg-slate-900 dark:text-slate-200">
                      {filtered.length}
                    </span>
                  </div>
                </div>
              </div>

              <div className="max-h-170 overflow-auto">
                <div className="min-w-230">
                  <div className="sticky top-0 z-10 grid grid-cols-[minmax(220px,1.7fr)_minmax(120px,0.75fr)_minmax(140px,0.85fr)_minmax(120px,0.75fr)_minmax(120px,0.75fr)_minmax(130px,0.8fr)] gap-3 border-b border-slate-200 bg-slate-50/95 px-4 py-2 text-[11px] font-bold uppercase tracking-wide text-muted-foreground backdrop-blur dark:border-slate-800 dark:bg-slate-900/95">
                    <span>Эрсдэл</span>
                    <span>Хариуцагч</span>
                    <span>NIST CSF</span>
                    <span>Анхны оноо</span>
                    <span>Үлдэгдэл</span>
                    <span>Арга хэмжээ</span>
                  </div>
                  <div className="divide-y divide-slate-100 dark:divide-slate-800">
                    {filtered.map((risk) => {
                      const level = risk.inherent_risk_level;
                      const treatment = risk.risk_treatment as Treatment | null;
                      const isApproved =
                        risk.risk_treatment_approval_status === "approved";
                      const treatmentMeta = treatment
                        ? TREATMENT_LABELS[treatment]
                        : null;
                      const treatmentDisplay = treatmentMeta
                        ? {
                            label: isApproved
                              ? treatmentMeta.approved
                              : treatmentMeta.pending,
                            color: isApproved
                              ? treatmentMeta.doneColor
                              : treatmentMeta.color,
                          }
                        : null;
                      const nistFn = nistFunctionCode(
                        risk.nist_csf_function,
                        risk.nist_csf_category,
                      );
                      const nistCategory = nistCategoryCode(
                        risk.nist_csf_category,
                        risk.nist_csf_function,
                      );
                      const owner = riskOwnerLabel(risk);
                      const residualLevel = risk.residual_risk_level;
                      const residualColor = residualLevel
                        ? riskLevelColor(residualLevel)
                        : "border-slate-200 bg-slate-50 text-muted-foreground dark:border-slate-800 dark:bg-slate-950";

                      return (
                        <div
                          key={risk.id}
                          className="grid w-full grid-cols-[minmax(220px,1.7fr)_minmax(120px,0.75fr)_minmax(140px,0.85fr)_minmax(120px,0.75fr)_minmax(120px,0.75fr)_minmax(130px,0.8fr)] items-center gap-3 px-4 py-3 text-left text-sm transition hover:bg-slate-50 dark:hover:bg-slate-900/50"
                        >
                          <div className="flex min-w-0 items-start gap-3">
                            <span
                              className={`mt-1 h-10 w-1 shrink-0 rounded-full ${riskLevelAccent(level)}`}
                            />
                            <div className="min-w-0">
                              <div className="flex flex-wrap items-center gap-1.5">
                                <span
                                  className={`rounded-full border px-2 py-0.5 text-[11px] font-bold ${riskLevelColor(level)}`}
                                >
                                  {riskLevelLabel(level)}
                                </span>
                              </div>
                              <p className="mt-1 line-clamp-2 font-semibold leading-snug">
                                {risk.risk_title}
                              </p>
                            </div>
                          </div>

                          <div className="min-w-0">
                            <p className="truncate font-medium">{owner}</p>
                          </div>

                          <div className="min-w-0">
                            {nistFn ? (
                              <span
                                className={`inline-flex rounded-md px-2 py-0.5 text-[11px] font-semibold ${NIST_COLORS[nistFn] ?? "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300"}`}
                              >
                                {nistFn} · {nistFunctionLabel(nistFn)}
                              </span>
                            ) : (
                              <span className="text-xs text-muted-foreground">
                                Тодорхойгүй
                              </span>
                            )}
                            <p className="mt-1 truncate text-xs text-muted-foreground">
                              {nistCategory || "Ангилал сонгоогүй"}
                            </p>
                          </div>

                          <div className="min-w-0">
                            <span
                              className={`inline-flex rounded-full border px-2 py-0.5 text-xs font-bold ${riskLevelColor(level)}`}
                            >
                              {risk.inherent_risk_score ?? "—"} ·{" "}
                              {riskLevelLabel(level)}
                            </span>
                          </div>

                          <div className="min-w-0">
                            <span
                              className={`inline-flex rounded-full border px-2 py-0.5 text-xs font-bold ${residualColor}`}
                            >
                              {risk.residual_risk_score ?? "—"} ·{" "}
                              {residualLevel
                                ? riskLevelLabel(residualLevel)
                                : "Тооцоогүй"}
                            </span>
                          </div>

                          <div className="min-w-0">
                            <Link
                              href={`/risks/${risk.id}`}
                              className={`inline-flex h-8 items-center justify-center rounded-md border px-3 text-[11px] font-bold shadow-sm transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 ${
                                treatmentDisplay
                                  ? treatmentDisplay.color
                                  : "border-slate-200 bg-white text-slate-950 hover:bg-slate-50 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100 dark:hover:bg-slate-900"
                              }`}
                            >
                              {treatmentDisplay
                                ? treatmentDisplay.label
                                : "Арга хэмжээ авах"}
                            </Link>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </section>
          </div>
        )}
      </div>
    </div>
  );
}
