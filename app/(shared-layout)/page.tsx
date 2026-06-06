"use client";

import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BookOpen,
  Building2,
  CheckCircle2,
  Database,
  Globe2,
  Info,
  Layers,
  RefreshCw,
  Shield,
  ShieldAlert,
  TrendingUp,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import {
  Legend,
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
} from "recharts";

// ─── Types ────────────────────────────────────────────────────────────────────

interface GapRow {
  id: number;
  subcategory_code: string;
  subcategory_name: string;
  nist_function: string;
  current_tier: number;
  target_tier: number;
  gap: number;
  priority: "Critical" | "High" | "Medium" | "Low";
  rationale: string;
  owner: string | null;
  due_date: string | null;
  updated_at: string;
}

interface ComplianceFnSummary {
  nist_function: string;
  total: number;
  assessed: number;
  compliant: number;
  partial: number;
  non_compliant: number;
  not_assessed: number;
  compliance_rate: number;
}

interface ComplianceSummary {
  total_subcategories: number;
  assessed: number;
  compliant: number;
  partial: number;
  non_compliant: number;
  not_assessed: number;
  compliance_rate: number;
  gap_count: number;
}

interface AssetScope {
  total_assets: number;
  critical_assets: number;
  mfa_coverage: number;
  encryption_coverage: number;
  logging_coverage: number;
  backup_coverage: number;
}

interface RingItem {
  name: string;
  nameMn: string;
  current: number;
  target: number;
  color: string;
}

interface ScopeSummary {
  departments: number;
  processes: number;
  assets: number;
  nist_subcategories: number;
  scope_status: string | null;
}

interface ScopeAssetRisk {
  asset_name: string;
  asset_type: string | null;
  internet_exposed: boolean;
  risk_count: number;
  highest_level: string;
}

interface RiskLevelCounts {
  Critical: number;
  High: number;
  Medium: number;
  Low: number;
  total: number;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const TIER_LABELS: Record<
  number,
  { label: string; desc: string; color: string }
> = {
  1: { label: "Tier 1", desc: "Partial", color: "text-red-500" },
  2: { label: "Tier 2", desc: "Risk Informed", color: "text-orange-500" },
  3: { label: "Tier 3", desc: "Repeatable", color: "text-yellow-500" },
  4: { label: "Tier 4", desc: "Adaptive", color: "text-green-500" },
};

const FUNCTION_COLORS: Record<string, string> = {
  Govern: "#8b5cf6",
  Identify: "#3b82f6",
  Protect: "#10b981",
  Detect: "#f59e0b",
  Respond: "#ef4444",
  Recover: "#6366f1",
};

const FUNCTION_MN: Record<string, string> = {
  Govern: "Засаглал",
  Identify: "Тодорхойлох",
  Protect: "Хамгаалах",
  Detect: "Илрүүлэх",
  Respond: "Хариу арга хэмжээ",
  Recover: "Сэргээх",
};

const FUNCTION_ORDER = [
  "Govern",
  "Identify",
  "Protect",
  "Detect",
  "Respond",
  "Recover",
];

// ─── Activity Rings ───────────────────────────────────────────────────────────

function ActivityRings({
  items,
  overallPct,
}: {
  items: RingItem[];
  overallPct: number;
}) {
  const cx = 130,
    cy = 130;
  const RING_W = 13,
    GAP = 5,
    BASE_R = 114;

  return (
    <div className="flex flex-col items-center gap-5">
      <svg
        width={cx * 2}
        height={cy * 2}
        className="overflow-visible drop-shadow-sm"
      >
        {/* Glow filter */}
        <defs>
          <filter
            id="activity-rings-glow"
            x="-40"
            y="-40"
            width={cx * 2 + 80}
            height={cy * 2 + 80}
            filterUnits="userSpaceOnUse"
          >
            <feGaussianBlur stdDeviation="2.5" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        <g aria-hidden="true">
          {items.map((item, i) => {
            const r = BASE_R - i * (RING_W + GAP);
            if (r < 8) return null;
            return (
              <circle
                key={`${item.name}-track`}
                cx={cx}
                cy={cy}
                r={r}
                fill="none"
                stroke={item.color}
                strokeWidth={RING_W}
                opacity={0.1}
              />
            );
          })}
        </g>

        <g>
          {items.map((item, i) => {
            const r = BASE_R - i * (RING_W + GAP);
            if (r < 8) return null;
            const circ = 2 * Math.PI * r;
            const pct = Math.min(
              item.target > 0 ? item.current / item.target : 0,
              1,
            );
            const filled = pct * circ;
            const isComplete = pct >= 0.995;
            return (
              <circle
                key={`${item.name}-progress`}
                cx={cx}
                cy={cy}
                r={r}
                fill="none"
                stroke={item.color}
                strokeWidth={RING_W}
                strokeDasharray={isComplete ? undefined : `${filled} ${circ}`}
                strokeLinecap={isComplete ? undefined : "round"}
                transform={`rotate(-90 ${cx} ${cy})`}
                filter="url(#activity-rings-glow)"
              />
            );
          })}
        </g>
      </svg>

      {/* Overall score */}
      <div className="text-center -mt-2">
        <span className="text-3xl font-black tabular-nums text-foreground">
          {overallPct}%
        </span>
      </div>

      {/* Legend */}
      <div className="grid grid-cols-2 gap-x-8 gap-y-2.5 w-full px-2">
        {items.map((item) => {
          const ratio = item.target > 0 ? item.current / item.target : 0;
          const pct = Math.min(Math.round(ratio * 100), 100);
          const achieved = ratio >= 1;
          const barW = Math.min(Math.max(4, pct), 100);
          return (
            <div key={item.name} className="space-y-1">
              <div className="flex items-center gap-2 min-w-0">
                <span
                  className="w-2.5 h-2.5 rounded-full shrink-0"
                  style={{ backgroundColor: item.color }}
                />
                <span className="text-xs text-muted-foreground flex-1 truncate">
                  {item.nameMn}
                </span>
                <span
                  className="text-xs font-bold tabular-nums"
                  style={{ color: achieved ? "#10b981" : item.color }}
                >
                  {achieved ? "✓" : ""}
                  {pct}%
                </span>
              </div>
              <div className="h-1 rounded-full bg-muted overflow-hidden">
                <div
                  className="h-full rounded-full"
                  style={{
                    width: `${barW}%`,
                    backgroundColor: achieved ? "#10b981" : item.color,
                    opacity: 0.7,
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Main ─────────────────────────────────────────────────────────────────────

export default function Home() {
  const [gaps, setGaps] = useState<GapRow[]>([]);
  const [complianceByFn, setComplianceByFn] = useState<ComplianceFnSummary[]>(
    [],
  );
  const [complianceSummary, setComplianceSummary] =
    useState<ComplianceSummary | null>(null);
  const [assetScope, setAssetScope] = useState<AssetScope | null>(null);
  const [dashSummary, setDashSummary] = useState<{
    health_score?: number;
    total_assets?: number;
    total_risks?: number;
    open_vulnerabilities?: number;
  } | null>(null);
  const [policyCompliance, setPolicyCompliance] = useState<{
    totalRequired: number;
    approvedCount: number;
    pendingCount: number;
    draftCount: number;
    compliancePct: number;
  } | null>(null);
  const [scopeSummary, setScopeSummary] = useState<ScopeSummary | null>(null);
  const [scopeAssetRisks, setScopeAssetRisks] = useState<ScopeAssetRisk[]>([]);
  const [riskLevelCounts, setRiskLevelCounts] = useState<RiskLevelCounts>({
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    total: 0,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // ── Fetch ──────────────────────────────────────────────────────────────────
  const fetchAll = async () => {
    setLoading(true);
    setError(null);
    try {
      const [profileRes, dashRes, scopeRes, riskRes, complianceRes] =
        await Promise.all([
          fetch("/api/csf-profile"),
          fetch("/api/dashboard"),
          fetch("/api/csf-scope"),
          fetch("/api/risk-register"),
          fetch("/api/nist-csf-compliance"),
        ]);
      if (!profileRes.ok) throw new Error("Профайл татаж чадсангүй");
      const profileData = await profileRes.json();
      setGaps(profileData.gaps ?? []);
      setAssetScope(profileData.assetScope ?? null);
      setPolicyCompliance(profileData.policyCompliance ?? null);
      if (complianceRes.ok) {
        const cd = await complianceRes.json();
        if (cd.success) {
          setComplianceByFn(cd.by_function ?? []);
          setComplianceSummary(cd.summary ?? null);
        }
      }
      if (dashRes.ok) {
        const dashData = await dashRes.json();
        setDashSummary(dashData.summary ?? null);
      }
      if (scopeRes.ok) {
        const scopeData = await scopeRes.json();
        const scope = scopeData.assessment_scope;
        const inScopeRows = (scopeData.rows ?? []).filter(
          (r: { scope_status: string; is_mandatory: boolean }) =>
            r.is_mandatory || r.scope_status === "in_scope",
        );
        setScopeSummary({
          departments: (scope?.selected_department_ids ?? []).length,
          processes: (scope?.selected_business_process_ids ?? []).length,
          assets: (scope?.selected_asset_ids ?? []).length,
          nist_subcategories: inScopeRows.length,
          scope_status: scope?.status ?? null,
        });
      }
      if (riskRes.ok) {
        const riskData = await riskRes.json();
        const risks: Array<{
          asset_name: string | null;
          asset_type: string | null;
          inherent_risk_level: string | null;
        }> = riskData.risks ?? [];
        const counts: RiskLevelCounts = {
          Critical: 0,
          High: 0,
          Medium: 0,
          Low: 0,
          total: risks.length,
        };
        const assetMap: Record<string, ScopeAssetRisk> = {};
        const levelOrder = ["Critical", "High", "Medium", "Low"];
        for (const r of risks) {
          const lvl = r.inherent_risk_level ?? "Low";
          if (lvl in counts) counts[lvl as keyof typeof counts]++;
          // Skip risks with no linked asset — they belong to the framework level,
          // not to a specific asset, so they shouldn't appear in the asset list.
          const name = r.asset_name;
          if (!name) continue;
          if (!assetMap[name])
            assetMap[name] = {
              asset_name: name,
              asset_type: r.asset_type,
              internet_exposed: false,
              risk_count: 0,
              highest_level: "Low",
            };
          assetMap[name].risk_count++;
          if (
            levelOrder.indexOf(lvl) <
            levelOrder.indexOf(assetMap[name].highest_level)
          ) {
            assetMap[name].highest_level = lvl;
          }
        }
        setRiskLevelCounts(counts);
        setScopeAssetRisks(
          Object.values(assetMap).sort((a, b) => b.risk_count - a.risk_count),
        );
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Алдаа гарлаа");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAll();
  }, []);

  // ── Derived ────────────────────────────────────────────────────────────────
  const radarData = useMemo(() => {
    const byFn: Record<string, { current: number[]; target: number[] }> = {};
    for (const fn of FUNCTION_ORDER) byFn[fn] = { current: [], target: [] };
    for (const g of gaps) {
      if (byFn[g.nist_function]) {
        byFn[g.nist_function].current.push(g.current_tier);
        byFn[g.nist_function].target.push(g.target_tier);
      }
    }
    const avg = (arr: number[]) =>
      arr.length
        ? +(arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(1)
        : 0;
    return FUNCTION_ORDER.map((fn) => ({
      function: FUNCTION_MN[fn] ?? fn,
      fullMark: 4,
      "Одоогийн түвшин": avg(byFn[fn].current),
      "Зорилтот түвшин": avg(byFn[fn].target),
    }));
  }, [gaps]);

  const ringData = useMemo<RingItem[]>(
    () =>
      FUNCTION_ORDER.map((fn) => {
        const d = complianceByFn.find((f) => f.nist_function === fn);
        return {
          name: fn,
          nameMn: FUNCTION_MN[fn] ?? fn,
          current: d?.compliance_rate ?? 0,
          target: 100,
          color: FUNCTION_COLORS[fn] ?? "#6b7280",
        };
      }),
    [complianceByFn],
  );

  const overallPct = useMemo(
    () => complianceSummary?.compliance_rate ?? 0,
    [complianceSummary],
  );

  const stats = useMemo(() => {
    const totalGaps = complianceSummary?.gap_count ?? 0;
    const compliantCount = complianceSummary?.compliant ?? 0;
    const totalSubcategories = complianceSummary?.total_subcategories ?? 0;
    return { totalGaps, compliantCount, totalSubcategories };
  }, [complianceSummary]);

  // ── Loading / Error ────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <div className="flex items-center gap-3 text-muted-foreground">
          <RefreshCw className="w-5 h-5 animate-spin" />
          <span>Ачааллаж байна…</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <div className="text-center space-y-3">
          <AlertTriangle className="w-10 h-10 text-red-500 mx-auto" />
          <p className="text-red-600 font-medium">{error}</p>
          <button
            onClick={fetchAll}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm"
          >
            Дахин оролдох
          </button>
        </div>
      </div>
    );
  }

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="space-y-6 pb-10 p-4 sm:p-6 md:p-8 select-none [&_button]:select-auto [&_a]:select-auto [&_input]:select-text">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-3">
            <Shield className="w-8 h-8 text-blue-600" />
            Хянах самбар
          </h1>
        </div>
        <button
          onClick={fetchAll}
          className="flex items-center gap-2 px-4 py-2 border border-border rounded-lg text-sm hover:bg-muted transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          Шинэчлэх
        </button>
      </div>

      {/* KPI Cards — row 1 */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <KpiCard
          icon={<Activity className="w-4 h-4 text-blue-500" />}
          value={`${dashSummary?.health_score ?? overallPct}%`}
          label="Аюулгүй байдлын индекс"
          accent="blue"
        />
        <KpiCard
          icon={<Layers className="w-4 h-4 text-indigo-500" />}
          value={dashSummary?.total_assets ?? assetScope?.total_assets ?? "—"}
          label="Нийт хөрөнгө"
          accent="indigo"
        />
        <KpiCard
          icon={<AlertTriangle className="w-4 h-4 text-orange-500" />}
          value={dashSummary?.total_risks ?? "—"}
          label="Нийт эрсдэл"
          accent="orange"
        />
        <KpiCard
          icon={<Shield className="w-4 h-4 text-red-500" />}
          value={stats.totalGaps}
          label="Нийцлийн зөрүү"
          accent="red"
        />
        <KpiCard
          icon={<CheckCircle2 className="w-4 h-4 text-emerald-500" />}
          value={`${stats.compliantCount} / ${stats.totalSubcategories}`}
          label="Хангасан дэд ангилал"
          accent="green"
        />
        <KpiCard
          icon={<TrendingUp className="w-4 h-4 text-green-500" />}
          value={`${overallPct}%`}
          label="NIST CSF нийцлийн хувь"
          accent="green"
        />
      </div>

      {/* Policy compliance banner */}
      {policyCompliance && policyCompliance.totalRequired > 0 && (
        <div
          className={`rounded-xl border p-4 flex flex-col sm:flex-row sm:items-center gap-4 ${
            policyCompliance.compliancePct >= 80
              ? "bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-900"
              : policyCompliance.compliancePct >= 40
                ? "bg-amber-50 dark:bg-amber-950/30 border-amber-200 dark:border-amber-900"
                : "bg-rose-50 dark:bg-rose-950/30 border-rose-200 dark:border-rose-900"
          }`}
        >
          <BookOpen
            className={`w-5 h-5 shrink-0 ${
              policyCompliance.compliancePct >= 80
                ? "text-emerald-600"
                : policyCompliance.compliancePct >= 40
                  ? "text-amber-600"
                  : "text-rose-600"
            }`}
          />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 mb-1.5">
              <span className="text-sm font-bold text-foreground">
                Дүрэм журмын нийцлийн түвшин
              </span>
              <span
                className={`text-sm font-black tabular-nums ${
                  policyCompliance.compliancePct >= 80
                    ? "text-emerald-600"
                    : policyCompliance.compliancePct >= 40
                      ? "text-amber-600"
                      : "text-rose-600"
                }`}
              >
                {policyCompliance.approvedCount} /{" "}
                {policyCompliance.totalRequired} батлагдсан (
                {policyCompliance.compliancePct}%)
              </span>
            </div>
            {/* Progress bar */}
            <div className="h-2 rounded-full bg-black/10 dark:bg-white/10 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${
                  policyCompliance.compliancePct >= 80
                    ? "bg-emerald-500"
                    : policyCompliance.compliancePct >= 40
                      ? "bg-amber-500"
                      : "bg-rose-500"
                }`}
                style={{
                  width: `${Math.max(policyCompliance.compliancePct, 3)}%`,
                }}
              />
            </div>
            <div className="flex gap-4 mt-1.5 text-xs text-muted-foreground">
              <span>
                ✓ Батлагдсан: <b>{policyCompliance.approvedCount}</b>
              </span>
              <span>
                ⏳ Зөвшөөрөл хүлээж: <b>{policyCompliance.pendingCount}</b>
              </span>
              <span>
                ✎ Ноорог: <b>{policyCompliance.draftCount}</b>
              </span>
            </div>
          </div>
          <a
            href="/policies"
            className={`shrink-0 text-xs font-semibold px-3 py-1.5 rounded-lg border transition-colors ${
              policyCompliance.compliancePct >= 80
                ? "border-emerald-300 text-emerald-700 hover:bg-emerald-100 dark:border-emerald-800 dark:text-emerald-400 dark:hover:bg-emerald-950"
                : policyCompliance.compliancePct >= 40
                  ? "border-amber-300 text-amber-700 hover:bg-amber-100 dark:border-amber-800 dark:text-amber-400 dark:hover:bg-amber-950"
                  : "border-rose-300 text-rose-700 hover:bg-rose-100 dark:border-rose-800 dark:text-rose-400 dark:hover:bg-rose-950"
            }`}
          >
            Дүрэм журам →
          </a>
        </div>
      )}

      {/* Charts — Radar + Activity Rings */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Radar chart */}
        <div className="lg:col-span-3 rounded-xl border border-border bg-card p-6 shadow-sm">
          <h2 className="text-base font-semibold text-foreground mb-1">
            Функцийн харьцуулалт
          </h2>
          <p className="text-xs text-muted-foreground mb-3">
            Tier 1–4 · Одоогийн болон зорилтот түвшний харьцуулалт
          </p>
          <ResponsiveContainer width="100%" height={320}>
            <RadarChart
              data={radarData}
              margin={{ top: 24, right: 48, bottom: 16, left: 48 }}
            >
              <PolarGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
              <PolarAngleAxis
                dataKey="function"
                tick={{
                  fontSize: 11,
                  fill: "hsl(var(--foreground))",
                  fontWeight: 600,
                }}
              />
              <PolarRadiusAxis
                angle={90}
                domain={[0, 4]}
                tick={{ fontSize: 9, fill: "hsl(var(--muted-foreground))" }}
                tickCount={5}
                tickFormatter={(v: number) => (v === 0 ? "" : `T${v}`)}
              />
              <Radar
                name="Одоогийн түвшин"
                dataKey="Одоогийн түвшин"
                stroke="#3b82f6"
                fill="#3b82f6"
                fillOpacity={0.25}
                strokeWidth={2.5}
                dot={(props: Record<string, unknown>) => {
                  const cx = props.cx as number;
                  const cy = props.cy as number;
                  const idx = props.index as number;
                  if (!cx || !cy) return <g key={idx} />;
                  return (
                    <g key={`cur-${idx}`}>
                      <circle
                        cx={cx}
                        cy={cy}
                        r={6}
                        fill="#3b82f6"
                        stroke="white"
                        strokeWidth={2}
                      />
                    </g>
                  );
                }}
              />
              <Radar
                name="Зорилтот түвшин"
                dataKey="Зорилтот түвшин"
                stroke="#10b981"
                fill="#10b981"
                fillOpacity={0.12}
                strokeWidth={2}
                strokeDasharray="6 3"
                dot={(props: Record<string, unknown>) => {
                  const cx = props.cx as number;
                  const cy = props.cy as number;
                  const idx = props.index as number;
                  if (!cx || !cy) return <g key={idx} />;
                  return (
                    <g key={`tgt-${idx}`}>
                      <circle
                        cx={cx}
                        cy={cy}
                        r={5}
                        fill="white"
                        stroke="#10b981"
                        strokeWidth={2.5}
                      />
                    </g>
                  );
                }}
              />
              <Legend wrapperStyle={{ fontSize: 12, paddingTop: 8 }} />
              <Tooltip
                formatter={(value, name) => [`Tier ${value}`, name as string]}
                contentStyle={{
                  backgroundColor: "hsl(var(--card))",
                  border: "1px solid hsl(var(--border))",
                  borderRadius: 10,
                  fontSize: 12,
                  boxShadow: "0 4px 16px rgba(0,0,0,0.08)",
                }}
              />
            </RadarChart>
          </ResponsiveContainer>

          {/* Per-function tier score cards */}
          <div className="mt-3 grid grid-cols-3 sm:grid-cols-6 gap-2">
            {radarData.map((d, i) => {
              const fn = FUNCTION_ORDER[i];
              const color = FUNCTION_COLORS[fn] ?? "#6b7280";
              const current = d["Одоогийн түвшин"];
              const target = d["Зорилтот түвшин"];
              const achieved = current >= target;
              return (
                <div
                  key={fn}
                  className="rounded-lg p-2 text-center"
                  style={{
                    backgroundColor: achieved ? "#10b98112" : `${color}12`,
                    border: `1px solid ${achieved ? "#10b98130" : `${color}25`}`,
                  }}
                >
                  <div
                    className="text-xl font-black tabular-nums"
                    style={{ color: achieved ? "#10b981" : color }}
                  >
                    T{current}
                  </div>
                  <div className="text-[10px] text-muted-foreground leading-tight mt-0.5 truncate font-medium">
                    {d.function}
                  </div>
                  <div
                    className="text-[10px] font-semibold mt-0.5"
                    style={{ color: achieved ? "#10b981" : "#ef4444" }}
                  >
                    {achieved ? `✓ T${target}` : `→ T${target}`}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Activity Rings */}
        <div className="lg:col-span-2 rounded-xl border border-border bg-card p-6 shadow-sm flex flex-col">
          <h2 className="text-base font-semibold text-foreground mb-1">
            Нийцтэй байдал
          </h2>
          <div className="flex-1 flex items-center justify-center">
            <ActivityRings items={ringData} overallPct={overallPct} />
          </div>
        </div>
      </div>

      {/* Asset scope */}
      {assetScope && (
        <div className="rounded-xl border border-border bg-card p-5 shadow-sm">
          <h2 className="text-base font-semibold text-foreground mb-3 flex items-center gap-2">
            <Info className="w-4 h-4 text-blue-500" />
            Хөрөнгийн хамрах хүрээ (автомат тооцоо)
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            {[
              { label: "Нийт хөрөнгө", value: assetScope.total_assets },
              { label: "Чухал хөрөнгө", value: assetScope.critical_assets },
              { label: "MFA", value: `${assetScope.mfa_coverage}%` },
              {
                label: "Шифрлэлт",
                value: `${assetScope.encryption_coverage}%`,
              },
              {
                label: "Лог хөтлөлт",
                value: `${assetScope.logging_coverage}%`,
              },
              {
                label: "Нөөцлөлт(Backup)",
                value: `${assetScope.backup_coverage}%`,
              },
            ].map(({ label, value }) => (
              <div
                key={label}
                className="bg-muted/40 rounded-lg p-3 text-center"
              >
                <div className="text-lg font-bold text-foreground">{value}</div>
                <div className="text-xs text-muted-foreground mt-0.5">
                  {label}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Risk Assessment Scope */}
      <div className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between gap-4 px-5 py-4 border-b border-border bg-muted/20 flex-wrap">
          <div>
            <h2 className="text-base font-bold text-foreground tracking-tight flex items-center gap-2">
              <Shield className="w-4 h-4 text-blue-500" />
              Эрсдэлийн үнэлгээний хамрах хүрээ ба дүгнэлт
            </h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              Эрсдэлийн үнэлгээнд хамрагдах хэлтэс, мэдээлллийн хөрөнгүүд болон
              NIST CSF-ийн дэд ангилалуудын хураангуй
            </p>
          </div>
          <a
            href="/csf-scope"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border text-xs font-semibold hover:bg-muted transition-colors"
          >
            Scope тохиргоо
            <ArrowRight className="w-3.5 h-3.5" />
          </a>
        </div>

        <div className="p-5 space-y-5">
          {/* Scope tiles */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              {
                label: "Хэлтэс",
                value: scopeSummary?.departments ?? 0,
                icon: Building2,
                color: "text-violet-600",
                bg: "bg-violet-500",
              },
              {
                label: "Бизнесийн процесс",
                value: scopeSummary?.processes ?? 0,
                icon: Database,
                color: "text-sky-600",
                bg: "bg-sky-500",
              },
              {
                label: "Мэдээллийн хөрөнгө",
                value: scopeSummary?.assets ?? 0,
                icon: Shield,
                color: "text-emerald-600",
                bg: "bg-emerald-500",
              },
              {
                label: "NIST CSF дэд ангилал",
                value: scopeSummary?.nist_subcategories ?? 0,
                icon: CheckCircle2,
                color: "text-amber-600",
                bg: "bg-amber-500",
              },
            ].map(({ label, value, icon: Icon, color, bg }) => (
              <div
                key={label}
                className="rounded-xl border bg-white p-4 shadow-sm dark:bg-slate-950"
              >
                <div className="flex items-center gap-3">
                  <div
                    className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${bg}`}
                  >
                    <Icon className="h-4 w-4 text-white" />
                  </div>
                  <div>
                    <p className="text-[10px] font-medium text-muted-foreground leading-tight">
                      {label}
                    </p>
                    <p className={`text-2xl font-bold leading-none ${color}`}>
                      {value}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Risk level breakdown + Asset risks */}
          {riskLevelCounts.total === 0 ? (
            <div className="flex flex-col items-center justify-center rounded-xl border border-dashed py-12 text-center">
              <ShieldAlert className="mb-3 h-9 w-9 text-muted-foreground/40" />
              <p className="text-sm font-medium text-muted-foreground">
                Эрсдэл тодорхойлогдоогүй байна
              </p>
              <p className="mt-1 text-xs text-muted-foreground">
                Эрсдэлийн бүртгэлд очиж эрсдэлүүдийг нэмнэ үү
              </p>
              <a
                href="/assessments"
                className="mt-3 flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold hover:bg-muted transition-colors"
              >
                Эрсдэл нэмэх <ArrowRight className="h-3.5 w-3.5" />
              </a>
            </div>
          ) : (
            <div className="grid gap-5 lg:grid-cols-2">
              {/* Risk level bars */}
              <div className="rounded-xl border bg-white p-4 dark:bg-slate-950">
                <h3 className="mb-4 text-sm font-semibold flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-amber-500" />
                  Эрсдэлийн түвшний хуваарилалт ({riskLevelCounts.total} нийт)
                </h3>
                <div className="space-y-3">
                  {(["Critical", "High", "Medium", "Low"] as const).map(
                    (lvl) => {
                      const META = {
                        Critical: {
                          label: "Маш өндөр",
                          color: "bg-red-500",
                          text: "text-red-700 dark:text-red-300",
                        },
                        High: {
                          label: "Өндөр",
                          color: "bg-orange-500",
                          text: "text-orange-700 dark:text-orange-300",
                        },
                        Medium: {
                          label: "Дунд",
                          color: "bg-yellow-400",
                          text: "text-yellow-700 dark:text-yellow-300",
                        },
                        Low: {
                          label: "Бага",
                          color: "bg-emerald-500",
                          text: "text-emerald-700 dark:text-emerald-300",
                        },
                      };
                      const m = META[lvl];
                      const count = riskLevelCounts[lvl];
                      const pct =
                        riskLevelCounts.total > 0
                          ? Math.round((count / riskLevelCounts.total) * 100)
                          : 0;
                      return (
                        <div key={lvl} className="space-y-1">
                          <div className="flex items-center justify-between text-xs">
                            <span className={`font-semibold ${m.text}`}>
                              {m.label}
                            </span>
                            <span className="font-bold">
                              {count}{" "}
                              <span className="font-normal text-muted-foreground">
                                ({pct}%)
                              </span>
                            </span>
                          </div>
                          <div className="h-2 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                            <div
                              className={`h-full rounded-full ${m.color}`}
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                        </div>
                      );
                    },
                  )}
                </div>
              </div>

              {/* Asset risks */}
              <div className="rounded-xl border bg-white p-4 dark:bg-slate-950">
                <h3 className="mb-4 text-sm font-semibold flex items-center gap-2">
                  <Database className="h-4 w-4 text-sky-500" />
                  Хамгийн их эрсдэлтэй хөрөнгүүд
                </h3>
                <div className="space-y-2 max-h-52 overflow-y-auto">
                  {scopeAssetRisks.map((a) => {
                    const LVL_DOT: Record<string, string> = {
                      Critical: "bg-red-500",
                      High: "bg-orange-500",
                      Medium: "bg-yellow-400",
                      Low: "bg-emerald-500",
                    };
                    const LVL_BADGE: Record<string, string> = {
                      Critical:
                        "border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950/30 dark:text-red-300",
                      High: "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-800 dark:bg-orange-950/30 dark:text-orange-300",
                      Medium:
                        "border-yellow-200 bg-yellow-50 text-yellow-700 dark:border-yellow-800 dark:bg-yellow-950/30 dark:text-yellow-300",
                      Low: "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-300",
                    };
                    const LVL_MN: Record<string, string> = {
                      Critical: "Критик",
                      High: "Өндөр",
                      Medium: "Дунд",
                      Low: "Бага",
                    };
                    return (
                      <div
                        key={a.asset_name}
                        className="flex items-center gap-3 rounded-lg border p-2.5"
                      >
                        <div
                          className={`h-2 w-2 shrink-0 rounded-full ${LVL_DOT[a.highest_level] ?? "bg-slate-400"}`}
                        />
                        <div className="min-w-0 flex-1">
                          <p className="truncate text-sm font-medium">
                            {a.asset_name}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            {a.asset_type}
                            {a.internet_exposed && (
                              <span className="ml-1.5 inline-flex items-center gap-0.5 text-orange-600">
                                <Globe2 className="h-2.5 w-2.5" />
                                Internet
                              </span>
                            )}
                          </p>
                        </div>
                        <div className="flex shrink-0 items-center gap-1.5">
                          <span
                            className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold ${LVL_BADGE[a.highest_level] ?? ""}`}
                          >
                            {LVL_MN[a.highest_level] ?? a.highest_level}
                          </span>
                          <span className="text-[10px] text-muted-foreground">
                            {a.risk_count} эрсдэл
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {/* Quick links */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1">
            {[
              { href: "/assessments", label: "Эрсдэлийн бүртгэл" },
              { href: "/assets", label: "Хөрөнгийн бүртгэл" },
              { href: "/controls", label: "Хяналтын зөвлөмж" },
              { href: "/reports", label: "Тайлан" },
            ].map(({ href, label }) => (
              <a
                key={href}
                href={href}
                className="flex items-center justify-between rounded-lg border px-3 py-2 text-xs font-medium hover:bg-muted transition-colors"
              >
                {label}
                <ArrowRight className="h-3.5 w-3.5 text-muted-foreground" />
              </a>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function KpiCard({
  icon,
  value,
  label,
  accent,
}: {
  icon: React.ReactNode;
  value: string | number;
  label: string;
  accent: "blue" | "indigo" | "orange" | "red" | "rose" | "green";
}) {
  const cls: Record<string, string> = {
    blue: "bg-blue-50   border-blue-200   dark:bg-slate-800 dark:border-slate-700",
    indigo:
      "bg-indigo-50 border-indigo-200 dark:bg-slate-800 dark:border-slate-700",
    orange:
      "bg-orange-50 border-orange-200 dark:bg-slate-800 dark:border-slate-700",
    red: "bg-red-50    border-red-200    dark:bg-slate-800 dark:border-slate-700",
    rose: "bg-rose-50   border-rose-200   dark:bg-slate-800 dark:border-slate-700",
    green:
      "bg-green-50  border-green-200  dark:bg-slate-800 dark:border-slate-700",
  };
  return (
    <div className={`kpi-card rounded-xl border p-4 shadow-sm ${cls[accent]}`}>
      <div className="mb-1">{icon}</div>
      <div className="text-2xl font-bold text-foreground">{value}</div>
      <div className="text-xs text-muted-foreground mt-0.5">{label}</div>
    </div>
  );
}
