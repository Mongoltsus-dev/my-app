"use client";

import { useAuth } from "@/app/context/AuthContext";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  ArrowRight,
  ChevronLeft,
  ChevronRight,
  CircleDashed,
  Filter,
  RefreshCw,
  Search,
  Target,
  XCircle,
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  ResponsiveContainer,
} from "recharts";

// ─── Types ────────────────────────────────────────────────────────────────────

type ComplianceStatus =
  | "compliant"
  | "partial"
  | "non_compliant"
  | "not_assessed";

type RiskSummary = {
  risk_register_id: number;
  risk_code: string | null;
  risk_title: string;
  risk_level: string | null;
  risk_score: number | null;
  asset_name: string | null;
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
  risks: RiskSummary[];
  affected_assets: string[];
  recommended_action: string;
};

type FunctionSummary = {
  nist_function: string;
  total: number;
  assessed: number;
  compliant: number;
  partial: number;
  non_compliant: number;
  not_assessed: number;
  compliance_rate: number;
};

type ComplianceResponse = {
  organization: unknown;
  asset_scope: unknown;
  summary: {
    total_subcategories: number;
    assessed: number;
    compliant: number;
    partial: number;
    non_compliant: number;
    not_assessed: number;
    compliance_rate: number;
    gap_count: number;
  };
  by_function: FunctionSummary[];
  rows: ComplianceRow[];
};

type GapFilter = "all" | "gap" | "not_assessed";

// ─── Constants ────────────────────────────────────────────────────────────────

const FUNCTION_ORDER = [
  "Govern",
  "Identify",
  "Protect",
  "Detect",
  "Respond",
  "Recover",
];

const FUNCTION_COLOR: Record<string, string> = {
  Govern: "#6366f1",
  Identify: "#3b82f6",
  Protect: "#10b981",
  Detect: "#f59e0b",
  Respond: "#f97316",
  Recover: "#8b5cf6",
};

const FUNCTION_MN: Record<string, string> = {
  Govern: "Засаглал",
  Identify: "Таних",
  Protect: "Хамгаалах",
  Detect: "Илрүүлэх",
  Respond: "Хариу үйлдэл",
  Recover: "Сэргээх",
};

const FUNCTION_CODE_TO_NAME: Record<string, string> = {
  GV: "Govern",
  ID: "Identify",
  PR: "Protect",
  DE: "Detect",
  RS: "Respond",
  RC: "Recover",
};

const GAP_FILTER_LABEL: Record<GapFilter, string> = {
  all: "Бүх зөрүү",
  gap: "Зөрүүтэй",
  not_assessed: "Үнэлээгүй",
};

const STATUS_LABEL: Record<ComplianceStatus, string> = {
  compliant: "Хангасан",
  partial: "Хэсэгчлэн хангасан",
  non_compliant: "Хангаагүй",
  not_assessed: "Үнэлээгүй",
};

const GAP_LEVEL_CONFIG: Record<number, { label: string; cls: string }> = {
  0: {
    label: "Зөрүүгүй",
    cls: "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-400",
  },
  1: {
    label: "Бага зөрүү · 1",
    cls: "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-400",
  },
  2: {
    label: "Дунд зөрүү · 2",
    cls: "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-800 dark:bg-orange-950/30 dark:text-orange-400",
  },
  3: {
    label: "Их зөрүү · 3",
    cls: "border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-900 dark:bg-rose-950/30 dark:text-rose-400",
  },
};

const PAGE_SIZE = 15;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function hasGap(row: ComplianceRow) {
  return (
    row.gap > 0 ||
    row.status === "partial" ||
    row.status === "non_compliant" ||
    row.status === "not_assessed"
  );
}

function gapLevelConfig(gap: number) {
  const clamped = Math.min(3, Math.max(0, Math.round(gap)));
  return GAP_LEVEL_CONFIG[clamped] ?? GAP_LEVEL_CONFIG[0];
}

function alignmentLabel(tier: number | null | undefined) {
  switch (tier) {
    case 1:
      return "Хангаагүй";
    case 2:
      return "Хэсэгчлэн";
    case 3:
      return "Хангасан";
    case 4:
      return "Бүрэн хангасан";
    default:
      return "Үнэлээгүй";
  }
}

function tierBadgeClass(tier: number | null | undefined) {
  switch (tier) {
    case 4:
      return "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-400";
    case 3:
      return "border-cyan-200 bg-cyan-50 text-cyan-700 dark:border-cyan-900 dark:bg-cyan-950/30 dark:text-cyan-400";
    case 2:
      return "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-400";
    case 1:
      return "border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-900 dark:bg-rose-950/30 dark:text-rose-400";
    default:
      return "border-slate-200 bg-slate-50 text-slate-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400";
  }
}

function functionRank(value: string) {
  const index = FUNCTION_ORDER.indexOf(normalizeFunction(value));
  return index === -1 ? FUNCTION_ORDER.length : index;
}

function normalizeFunction(value: string | null | undefined) {
  if (!value) return "";
  if (FUNCTION_ORDER.includes(value)) return value;
  return FUNCTION_CODE_TO_NAME[value] ?? value;
}

function rowFunction(row: ComplianceRow) {
  return (
    normalizeFunction(row.nist_function) ||
    normalizeFunction(row.function_code) ||
    FUNCTION_CODE_TO_NAME[row.subcategory_id?.split(".")[0] ?? ""] ||
    ""
  );
}

function sortRows(a: ComplianceRow, b: ComplianceRow) {
  const gapDelta = Number(hasGap(b)) - Number(hasGap(a));
  if (gapDelta !== 0) return gapDelta;
  const gapSizeDelta = b.gap - a.gap;
  if (gapSizeDelta !== 0) return gapSizeDelta;
  const functionDelta =
    functionRank(a.nist_function) - functionRank(b.nist_function);
  if (functionDelta !== 0) return functionDelta;
  return a.subcategory_id.localeCompare(b.subcategory_id);
}

function gapExplanation(row: ComplianceRow) {
  const current = alignmentLabel(row.current_tier);
  const target = alignmentLabel(row.target_tier);
  if (row.status === "not_assessed" || row.current_tier == null) {
    return `Одоогийн хэрэгжилт үнэлэгдээгүй байна. Зорилтот төлөв нь "${target}" тул хэрэгжилтийн нотолгоо, хариуцах эзэн, үнэлгээний үр дүнг бүртгэх шаардлагатай.`;
  }
  if (!hasGap(row)) {
    return "Одоогийн төлөв зорилтот түвшинд хүрсэн байна.";
  }
  return `Одоогийн төлөв "${current}", зорилтот төлөв "${target}". Энэ зөрүүг хаахын тулд бодлого, хяналт, нотолгоо болон хэрэгжилтийн давтамжийг тодорхой болгож шинэчилнэ.`;
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function GapAnalysisPage() {
  const { user } = useAuth();
  const router = useRouter();
  const [data, setData] = useState<ComplianceResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [gapFilter, setGapFilter] = useState<GapFilter>("all");
  const [functionFilter, setFunctionFilter] = useState("all");
  const [page, setPage] = useState(1);

  useEffect(() => {
    if (!user) router.push("/auth/login");
  }, [user, router]);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/nist-csf-compliance");
      if (res.ok) setData(await res.json());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (user) fetchData();
  }, [fetchData, user]);

  useEffect(() => {
    setPage(1);
  }, [search, gapFilter, functionFilter]);

  const filteredRows = useMemo(() => {
    const q = search.trim().toLowerCase();
    return (data?.rows ?? [])
      .filter((row) => {
        if (!hasGap(row)) return false;
        if (functionFilter !== "all" && rowFunction(row) !== functionFilter)
          return false;
        if (gapFilter === "gap" && row.status !== "non_compliant") return false;
        if (gapFilter === "not_assessed" && row.status !== "not_assessed")
          return false;
        if (!q) return true;
        return [
          row.subcategory_id,
          row.title,
          row.outcome,
          rowFunction(row),
          row.category_code,
          row.category_name,
          gapExplanation(row),
          alignmentLabel(row.current_tier),
          alignmentLabel(row.target_tier),
          STATUS_LABEL[row.status],
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase()
          .includes(q);
      })
      .sort(sortRows);
  }, [data, functionFilter, gapFilter, search]);

  const totalPages = Math.max(1, Math.ceil(filteredRows.length / PAGE_SIZE));
  const pagedRows = filteredRows.slice(
    (page - 1) * PAGE_SIZE,
    page * PAGE_SIZE,
  );

  const summary = data?.summary;
  const total = summary?.total_subcategories ?? 0;
  const gapRows = useMemo(
    () => (data?.rows ?? []).filter((row) => hasGap(row)),
    [data],
  );
  const gapTotal = gapRows.length;
  const smallGap = gapRows.filter((row) => row.gap === 1).length;
  const mediumGap = gapRows.filter((row) => row.gap === 2).length;
  const highGap = gapRows.filter((row) => row.gap >= 3).length;
  const notAssessed = gapRows.filter(
    (row) => row.status === "not_assessed",
  ).length;

  const radarData = useMemo(
    () =>
      (data?.by_function ?? []).map((fn) => ({
        function: FUNCTION_MN[fn.nist_function] ?? fn.nist_function,
        compliance: fn.compliance_rate,
      })),
    [data],
  );

  if (!user) return null;

  return (
    <div className="app-page p-4 pb-8 sm:p-6 md:p-8">
      <div className="mx-auto max-w-7xl space-y-6">
        {/* ── Header ── */}
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h1 className="text-3xl font-bold sm:text-4xl">
              Зөрүүгийн шинжилгээ
            </h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Зөвхөн одоогийн төлөв зорилтот түвшинд хүрээгүй NIST CSF дэд
              ангиллуудыг харуулна.
            </p>
          </div>
          <div className="flex flex-wrap gap-2 shrink-0">
            <Button
              variant="outline"
              onClick={fetchData}
              disabled={loading}
              className="gap-2"
            >
              <RefreshCw
                className={`h-4 w-4 ${loading ? "animate-spin" : ""}`}
              />
              Шинэчлэх
            </Button>
            <Link href="/csf-scope">
              <Button variant="outline" className="gap-2">
                <Target className="h-4 w-4" />
                CSF хамрах хүрээ
              </Button>
            </Link>
          </div>
        </div>

        {/* ── Summary tiles ── */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <SummaryTile
            icon={<XCircle className="h-4 w-4 text-rose-600" />}
            label="Нийт зөрүү"
            value={gapTotal}
            sub={total > 0 ? `${total} дэд ангиллаас` : undefined}
            cls="border-rose-200 bg-rose-50 dark:border-rose-900 dark:bg-rose-950/20"
          />
          <SummaryTile
            icon={<CircleDashed className="h-4 w-4 text-orange-600" />}
            label="Их зөрүү"
            value={highGap}
            sub="3 ба түүнээс дээш түвшин"
            cls="border-orange-200 bg-orange-50 dark:border-orange-900 dark:bg-orange-950/20"
          />
          <SummaryTile
            icon={<Target className="h-4 w-4 text-amber-600" />}
            label="Дунд / бага зөрүү"
            value={mediumGap + smallGap}
            sub={`${mediumGap} дунд · ${smallGap} бага`}
            cls="border-amber-200 bg-amber-50 dark:border-amber-900 dark:bg-amber-950/20"
          />
          <SummaryTile
            icon={
              <span className="h-4 w-4 text-slate-500 text-xs font-bold flex items-center justify-center">
                ?
              </span>
            }
            label="Үнэлээгүй"
            value={notAssessed}
            sub="Одоогийн төлөв тодорхойгүй"
            cls="border-slate-200 bg-slate-50 dark:border-slate-700 dark:bg-slate-900/40"
          />
        </div>

        {/* ── Compliance overview: score + radar + per-function bars ── */}
        {data && !loading && (
          <div className="grid gap-4 lg:grid-cols-[200px_1fr]">
            {/* Score card */}
            <div className="flex flex-col items-center justify-center rounded-xl border bg-white p-5 shadow-sm dark:bg-slate-950">
              <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                Нийт нийцлийн хувь
              </p>
              <p
                className="mt-2 text-5xl font-black leading-none"
                style={{
                  color:
                    (summary?.compliance_rate ?? 0) >= 70
                      ? "#10b981"
                      : (summary?.compliance_rate ?? 0) >= 40
                        ? "#f59e0b"
                        : "#ef4444",
                }}
              >
                {summary?.compliance_rate ?? 0}%
              </p>
              <p className="mt-2 text-center text-[11px] text-muted-foreground">
                {summary?.compliant ?? 0} / {summary?.assessed ?? 0} дэд ангилал
                хангасан
              </p>
              <div className="mt-4 w-full space-y-1.5">
                {(
                  [
                    {
                      label: "Хангасан",
                      value: summary?.compliant ?? 0,
                      cls: "bg-emerald-500",
                    },
                    {
                      label: "Хэсэгчлэн",
                      value: summary?.partial ?? 0,
                      cls: "bg-amber-400",
                    },
                    {
                      label: "Хангаагүй",
                      value: summary?.non_compliant ?? 0,
                      cls: "bg-rose-500",
                    },
                    {
                      label: "Үнэлээгүй",
                      value: summary?.not_assessed ?? 0,
                      cls: "bg-slate-300 dark:bg-slate-600",
                    },
                  ] as const
                ).map(({ label, value, cls }) => (
                  <div key={label} className="flex items-center gap-2 text-xs">
                    <span className={`h-2 w-2 shrink-0 rounded-full ${cls}`} />
                    <span className="flex-1 text-muted-foreground">
                      {label}
                    </span>
                    <span className="font-semibold">{value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Radar + per-function bars */}
            <div className="rounded-xl border bg-white p-4 shadow-sm dark:bg-slate-950">
              <div className="grid gap-4 md:grid-cols-[200px_1fr]">
                {/* Radar chart */}
                <div>
                  <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                    Функцийн хамрах хүрээ
                  </p>
                  <ResponsiveContainer width="100%" height={190}>
                    <RadarChart
                      data={radarData}
                      margin={{ top: 10, right: 20, bottom: 10, left: 20 }}
                    >
                      <PolarGrid stroke="#e2e8f0" />
                      <PolarAngleAxis
                        dataKey="function"
                        tick={{ fontSize: 9, fill: "#64748b", fontWeight: 600 }}
                      />
                      <PolarRadiusAxis
                        domain={[0, 100]}
                        tick={false}
                        axisLine={false}
                      />
                      <Radar
                        name="Нийцлийн хувь"
                        dataKey="compliance"
                        stroke="#3b82f6"
                        fill="#3b82f6"
                        fillOpacity={0.2}
                        strokeWidth={2}
                      />
                    </RadarChart>
                  </ResponsiveContainer>
                </div>

                {/* Per-function progress bars */}
                <div>
                  <p className="mb-3 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                    Функцийн дэлгэрэнгүй
                  </p>
                  <div className="space-y-3">
                    {(data?.by_function ?? []).map((fn) => {
                      const name =
                        FUNCTION_MN[fn.nist_function] ?? fn.nist_function;
                      const color =
                        FUNCTION_COLOR[fn.nist_function] ?? "#64748b";
                      const total = fn.total || 1;
                      const compliantPct = Math.round(
                        (fn.compliant / total) * 100,
                      );
                      const partialPct = Math.round((fn.partial / total) * 100);
                      const nonPct = Math.round(
                        (fn.non_compliant / total) * 100,
                      );
                      const naoPct = Math.round(
                        (fn.not_assessed / total) * 100,
                      );
                      return (
                        <div key={fn.nist_function}>
                          <div className="mb-1 flex items-center justify-between gap-2">
                            <span
                              className="text-[11px] font-semibold"
                              style={{ color }}
                            >
                              {name}
                            </span>
                            <span className="text-[11px] font-bold text-muted-foreground">
                              {fn.compliance_rate}%
                            </span>
                          </div>
                          <div className="flex h-3 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                            {compliantPct > 0 && (
                              <div
                                className="bg-emerald-500 transition-all"
                                style={{ width: `${compliantPct}%` }}
                                title={`Хангасан: ${fn.compliant}`}
                              />
                            )}
                            {partialPct > 0 && (
                              <div
                                className="bg-amber-400 transition-all"
                                style={{ width: `${partialPct}%` }}
                                title={`Хэсэгчлэн: ${fn.partial}`}
                              />
                            )}
                            {nonPct > 0 && (
                              <div
                                className="bg-rose-500 transition-all"
                                style={{ width: `${nonPct}%` }}
                                title={`Хангаагүй: ${fn.non_compliant}`}
                              />
                            )}
                            {naoPct > 0 && (
                              <div
                                className="bg-slate-300 dark:bg-slate-600 transition-all"
                                style={{ width: `${naoPct}%` }}
                                title={`Үнэлээгүй: ${fn.not_assessed}`}
                              />
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                  <div className="mt-3 flex flex-wrap gap-3 text-[10px] font-medium text-muted-foreground">
                    {[
                      { label: "Хангасан", cls: "bg-emerald-500" },
                      { label: "Хэсэгчлэн", cls: "bg-amber-400" },
                      { label: "Хангаагүй", cls: "bg-rose-500" },
                      {
                        label: "Үнэлээгүй",
                        cls: "bg-slate-300 dark:bg-slate-600",
                      },
                    ].map(({ label, cls }) => (
                      <span key={label} className="flex items-center gap-1">
                        <span
                          className={`inline-block h-2 w-3 rounded-sm ${cls}`}
                        />
                        {label}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── Function filter chips ── */}
        {data && (
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setFunctionFilter("all")}
              className={`rounded-full border px-3 py-1 text-xs font-semibold transition-colors ${
                functionFilter === "all"
                  ? "border-slate-900 bg-slate-900 text-white dark:border-slate-100 dark:bg-slate-100 dark:text-slate-900"
                  : "border-border text-muted-foreground hover:bg-muted"
              }`}
            >
              Бүгд
            </button>
            {FUNCTION_ORDER.map((fn) => {
              const gapCount = gapRows.filter(
                (row) => rowFunction(row) === fn,
              ).length;
              const color = FUNCTION_COLOR[fn];
              const active = functionFilter === fn;
              return (
                <button
                  key={fn}
                  onClick={() =>
                    setFunctionFilter((v) => (v === fn ? "all" : fn))
                  }
                  className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold transition-colors ${
                    active
                      ? "text-white"
                      : "border-border text-muted-foreground hover:bg-muted"
                  }`}
                  style={
                    active
                      ? { backgroundColor: color, borderColor: color }
                      : undefined
                  }
                >
                  <span
                    className="h-2 w-2 rounded-full shrink-0"
                    style={{
                      backgroundColor: active ? "rgba(255,255,255,0.7)" : color,
                    }}
                  />
                  {FUNCTION_MN[fn] ?? fn}
                  <span
                    className={`${active ? "text-white/80" : "text-muted-foreground"}`}
                  >
                    {gapCount}
                  </span>
                </button>
              );
            })}
          </div>
        )}

        {/* ── Search + gap filter ── */}
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="NIST код, функц, шаардлагаар хайх..."
              className="pl-9"
            />
          </div>
          <div className="flex items-center gap-1.5">
            <Filter className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
            {(["all", "gap", "not_assessed"] as const).map((f) => (
              <Button
                key={f}
                size="sm"
                variant={gapFilter === f ? "default" : "outline"}
                className="h-7 px-2.5 text-xs"
                onClick={() => setGapFilter(f)}
              >
                {GAP_FILTER_LABEL[f]}
              </Button>
            ))}
          </div>
        </div>

        {/* ── Gap table ── */}
        {loading ? (
          <div className="rounded-xl border bg-white p-10 text-center text-muted-foreground dark:bg-slate-950">
            Ачааллаж байна...
          </div>
        ) : !data ? (
          <div className="rounded-xl border bg-white p-10 text-center text-muted-foreground dark:bg-slate-950">
            Өгөгдөл уншиж чадсангүй.
          </div>
        ) : filteredRows.length === 0 ? (
          <div className="rounded-xl border bg-white p-10 text-center text-muted-foreground dark:bg-slate-950">
            Шүүлтүүрт тохирох зөрүү олдсонгүй.
          </div>
        ) : (
          <div className="overflow-hidden rounded-xl border bg-white shadow-sm dark:bg-slate-950">
            {/* Table header row */}
            <div className="flex items-center justify-between gap-2 border-b px-4 py-3">
              <div>
                <h2 className="text-sm font-bold">
                  Одоогийн ба зорилтот түвшний зөрүү
                </h2>
              </div>
              <p className="text-xs text-muted-foreground shrink-0">
                {page}/{totalPages} хуудас
              </p>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b bg-slate-50 text-left text-[11px] font-semibold uppercase tracking-wide text-slate-500 dark:bg-slate-900/60 dark:text-slate-400">
                  <tr>
                    <th className="px-4 py-2.5 whitespace-nowrap">NIST код</th>
                    <th className="px-4 py-2.5 min-w-md">Шаардлага</th>
                    <th className="px-4 py-2.5 whitespace-nowrap text-center">
                      Одоогийн төлөв
                    </th>
                    <th className="px-2 py-2.5 text-center" />
                    <th className="px-4 py-2.5 whitespace-nowrap text-center">
                      Зорилтот төлөв
                    </th>
                    <th className="px-4 py-2.5 whitespace-nowrap text-center">
                      Зөрүү
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {pagedRows.map((row) => {
                    const cfg = gapLevelConfig(row.gap);
                    const isGap = hasGap(row);
                    return (
                      <tr
                        key={row.subcategory_id}
                        className={`align-middle transition-colors hover:bg-slate-50/60 dark:hover:bg-slate-900/30 ${
                          isGap && row.gap >= 2
                            ? "bg-rose-50/20 dark:bg-rose-950/5"
                            : ""
                        }`}
                      >
                          {/* NIST Code */}
                          <td className="px-4 py-3">
                            <Badge className="border border-blue-200 bg-blue-50 font-mono text-[11px] text-blue-700 dark:border-blue-900 dark:bg-blue-950/30 dark:text-blue-300 whitespace-nowrap">
                              {row.subcategory_id}
                            </Badge>
                            <p
                              className="mt-0.5 text-[10px] text-muted-foreground"
                              style={{
                                color: FUNCTION_COLOR[rowFunction(row)],
                              }}
                            >
                              {FUNCTION_MN[rowFunction(row)] ??
                                rowFunction(row)}
                            </p>
                          </td>

                          {/* Requirement */}
                          <td className="px-4 py-3 min-w-md max-w-2xl">
                            <p className="text-xs font-medium leading-5 line-clamp-3">
                              {row.outcome || row.title}
                            </p>
                          </td>

                          {/* Current state */}
                          <td className="px-4 py-3 text-center">
                            <span
                              className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold whitespace-nowrap ${tierBadgeClass(row.current_tier)}`}
                            >
                              {alignmentLabel(row.current_tier)}
                            </span>
                          </td>

                          {/* Arrow */}
                          <td className="px-1 py-3 text-center">
                            <ArrowRight
                              className={`h-3.5 w-3.5 mx-auto ${isGap ? "text-rose-400" : "text-emerald-400"}`}
                            />
                          </td>

                          {/* Target state */}
                          <td className="px-4 py-3 text-center">
                            <span
                              className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold whitespace-nowrap ${tierBadgeClass(row.target_tier)}`}
                            >
                              {alignmentLabel(row.target_tier)}
                            </span>
                          </td>

                          {/* Gap */}
                          <td className="px-4 py-3 text-center">
                            <span
                              className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-bold whitespace-nowrap ${cfg.cls}`}
                            >
                              {cfg.label}
                            </span>
                          </td>
                        </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between border-t px-4 py-3">
                <p className="text-xs text-muted-foreground">
                  {(page - 1) * PAGE_SIZE + 1}–
                  {Math.min(page * PAGE_SIZE, filteredRows.length)} /{" "}
                  {filteredRows.length}
                </p>
                <div className="flex items-center gap-1">
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-7 w-7 p-0"
                    disabled={page === 1}
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                  >
                    <ChevronLeft className="h-3.5 w-3.5" />
                  </Button>
                  {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                    let p: number;
                    if (totalPages <= 5) p = i + 1;
                    else if (page <= 3) p = i + 1;
                    else if (page >= totalPages - 2) p = totalPages - 4 + i;
                    else p = page - 2 + i;
                    return (
                      <Button
                        key={p}
                        variant={page === p ? "default" : "outline"}
                        size="sm"
                        className="h-7 w-7 p-0 text-xs"
                        onClick={() => setPage(p)}
                      >
                        {p}
                      </Button>
                    );
                  })}
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-7 w-7 p-0"
                    disabled={page === totalPages}
                    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  >
                    <ChevronRight className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Sub-component ────────────────────────────────────────────────────────────

function SummaryTile({
  icon,
  label,
  value,
  sub,
  cls,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  sub?: string;
  cls: string;
}) {
  return (
    <div className={`rounded-xl border p-4 ${cls}`}>
      <div className="flex items-center justify-between gap-2">
        {icon}
        <span className="text-2xl font-black leading-none">{value}</span>
      </div>
      <p className="mt-2 text-xs font-semibold">{label}</p>
      {sub && <p className="mt-0.5 text-[10px] text-muted-foreground">{sub}</p>}
    </div>
  );
}
