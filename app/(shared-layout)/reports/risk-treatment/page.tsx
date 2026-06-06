"use client";

import { useAuth } from "@/app/context/AuthContext";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  ArrowRightLeft,
  Ban,
  CalendarDays,
  CheckCircle2,
  Download,
  Gauge,
  Shield,
  TrendingDown,
  UserRound,
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { Cell, Pie, PieChart, Tooltip } from "recharts";

interface SelectedControl {
  control_name: string;
  status: string;
  assigned_to: string | null;
}

interface RiskRow {
  risk_id: number;
  risk_code: string;
  risk_title: string;
  threat_name: string | null;
  nist_csf_function: string;
  nist_csf_category: string;
  department_control_owner: string | null;
  risk_treatment: string | null;
  treatment_rationale: string | null;
  treatment_owner: string | null;
  treatment_date: string | null;
  asset_name: string;
  asset_type: string;
  criticality: string;
  inherent_score: number;
  inherent_level: string;
  inherent_likelihood: number;
  inherent_impact: number;
  residual_risk_score: number | null;
  residual_risk_level: string | null;
  inherent_review_status: string | null;
  selected_controls: SelectedControl[] | null;
}

interface ReportData {
  generated_at: string;
  total: number;
  treated: number;
  untreated: number;
  coverage_pct: number;
  counts: Record<string, number>;
  by_treatment: Record<string, RiskRow[]>;
  level_matrix: Record<string, Record<string, number>>;
}

const TREATMENT_CONFIG = [
  {
    key: "Treat",
    label: "Treat",
    labelMn: "Бууруулах",
    Icon: Shield,
    description: "Хяналт хэрэгжүүлж магадлал эсвэл нөлөөллийг бууруулна",
    iconCls: "text-blue-500",
    badgeCls:
      "bg-blue-500/10 text-blue-700 dark:text-blue-300 border-blue-500/20",
    headerCls:
      "border-blue-200 dark:border-blue-900/40 bg-blue-50/60 dark:bg-blue-950/20",
    barCls: "bg-blue-500",
    hex: "#3b82f6",
    textCls: "text-blue-600",
    ringCls: "ring-blue-500/20 bg-blue-500/8",
  },
  {
    key: "Transfer",
    label: "Transfer",
    labelMn: "Шилжүүлэх",
    Icon: ArrowRightLeft,
    description: "Даатгал, гэрээ эсвэл гуравдагч тал руу эрсдэлийг шилжүүлнэ",
    iconCls: "text-violet-500",
    badgeCls:
      "bg-violet-500/10 text-violet-700 dark:text-violet-300 border-violet-500/20",
    headerCls:
      "border-violet-200 dark:border-violet-900/40 bg-violet-50/60 dark:bg-violet-950/20",
    barCls: "bg-violet-500",
    hex: "#8b5cf6",
    textCls: "text-violet-600",
    ringCls: "ring-violet-500/20 bg-violet-500/8",
  },
  {
    key: "Tolerate",
    label: "Tolerate",
    labelMn: "Хүлээн зөвшөөрөх",
    Icon: CheckCircle2,
    description: "Эрсдэлийг appetite/зөвшөөрөгдөх түвшинд хүлээн зөвшөөрнө",
    iconCls: "text-emerald-500",
    badgeCls:
      "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/20",
    headerCls:
      "border-emerald-200 dark:border-emerald-900/40 bg-emerald-50/60 dark:bg-emerald-950/20",
    barCls: "bg-emerald-500",
    hex: "#10b981",
    textCls: "text-emerald-600",
    ringCls: "ring-emerald-500/20 bg-emerald-500/8",
  },
  {
    key: "Terminate",
    label: "Terminate",
    labelMn: "Зогсоох",
    Icon: Ban,
    description: "Эрсдэл үүсгэж буй үйл ажиллагаа, exposure-ийг зогсооно",
    iconCls: "text-rose-500",
    badgeCls:
      "bg-rose-500/10 text-rose-700 dark:text-rose-300 border-rose-500/20",
    headerCls:
      "border-rose-200 dark:border-rose-900/40 bg-rose-50/60 dark:bg-rose-950/20",
    barCls: "bg-rose-500",
    hex: "#f43f5e",
    textCls: "text-rose-600",
    ringCls: "ring-rose-500/20 bg-rose-500/8",
  },
  {
    key: "Untreated",
    label: "Untreated",
    labelMn: "Шийдвэрлээгүй",
    Icon: null,
    description: "Арга хэмжээний шийдвэр бүртгэгдээгүй",
    iconCls: "text-muted-foreground",
    badgeCls:
      "bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-500/20",
    headerCls:
      "border-amber-200 dark:border-amber-900/40 bg-amber-50/60 dark:bg-amber-950/20",
    barCls: "bg-muted-foreground",
    hex: "#94a3b8",
    textCls: "text-amber-600",
    ringCls: "ring-amber-500/20 bg-amber-500/8",
  },
] as const;

const LEVELS = ["Critical", "High", "Medium", "Low"] as const;

const LEVEL_STYLE: Record<string, string> = {
  Critical: "bg-rose-500/10 text-rose-600 border-rose-500/20",
  High: "bg-orange-500/10 text-orange-600 border-orange-500/20",
  Medium: "bg-amber-400/10 text-amber-600 border-amber-500/20",
  Low: "bg-emerald-500/10 text-emerald-600 border-emerald-500/20",
};

const LEVEL_LABELS: Record<string, string> = {
  Critical: "Ноцтой",
  High: "Өндөр",
  Medium: "Дунд",
  Low: "Бага",
};

const LEVEL_ACCENT: Record<string, string> = {
  Critical: "from-rose-500 to-red-500",
  High: "from-orange-500 to-amber-500",
  Medium: "from-amber-400 to-yellow-500",
  Low: "from-emerald-500 to-teal-500",
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function levelStyle(level: string | null) {
  return (
    LEVEL_STYLE[level ?? ""] ?? "bg-muted text-muted-foreground border-border"
  );
}

function levelLabel(level: string | null | undefined) {
  return LEVEL_LABELS[level ?? ""] ?? level ?? "Тодорхойгүй";
}

function levelAccent(level: string | null | undefined) {
  return LEVEL_ACCENT[level ?? ""] ?? "from-slate-400 to-slate-500";
}

function reductionPct(inherent: number, residual: number | null) {
  if (!residual || inherent === 0) return null;
  return Math.max(0, Math.round((1 - residual / inherent) * 100));
}

function reductionTone(value: number | null) {
  if (value == null) return "text-muted-foreground";
  if (value >= 50) return "text-emerald-600";
  if (value >= 20) return "text-amber-600";
  return "text-rose-600";
}

function reductionBarWidth(value: number | null) {
  if (value == null) return "0%";
  return `${Math.min(Math.max(value, 0), 100)}%`;
}

const THREAT_NAME_MN: Record<string, string> = {
  "Data Exfiltration": "өгөгдөл гадагш алдагдах",
  "Unauthorized Access": "зөвшөөрөлгүй хандалт",
  "Credential Theft": "нэвтрэх эрхийн мэдээлэл алдагдах",
  "Denial of Service": "үйлчилгээ тасалдах",
  "DDoS Attack": "DDoS халдлага",
  Malware: "хортой кодын халдлага",
  Ransomware: "ransomware халдлага",
  "Privilege Escalation": "эрхийн түвшин нэмэгдүүлэх халдлага",
};

function threatMn(name: string | null | undefined) {
  if (!name) return "мэдээллийн аюулгүй байдлын";
  return THREAT_NAME_MN[name] ?? name;
}

function displayRiskTitle(risk: RiskRow) {
  const title = risk.risk_title ?? "";
  const lower = title.toLowerCase();
  if (
    lower.includes("internet exposure") ||
    lower.includes("internet-exposed") ||
    title.includes("Интернет өртөлт")
  ) {
    return `${risk.asset_name} нь нийтийн интернетээс хандах боломжтой тул ${threatMn(
      risk.threat_name,
    )} эрсдэл нэмэгдсэн`;
  }
  return title.replaceAll("Data Exfiltration", "өгөгдөл гадагш алдагдах");
}

function downloadRiskTreatment(format: "csv" | "xls") {
  window.location.href = `/api/reports/export?type=risk-treatment&format=${format}`;
}

function downloadRiskSummary(format: "csv" | "xls") {
  window.location.href = `/api/reports/export?type=risk-summary&format=${format}`;
}

// ─── Coverage Ring ────────────────────────────────────────────────────────────

function CoverageRing({ pct, total }: { pct: number; total: number }) {
  const r = 52;
  const circ = 2 * Math.PI * r;
  const filled = Math.min(pct / 100, 1) * circ;
  const color = pct >= 80 ? "#10b981" : pct >= 50 ? "#f59e0b" : "#ef4444";

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative flex items-center justify-center">
        <svg width={136} height={136} style={{ transform: "rotate(-90deg)" }}>
          <circle
            cx={68}
            cy={68}
            r={r}
            fill="none"
            stroke="currentColor"
            strokeWidth={11}
            className="text-muted/25"
          />
          <circle
            cx={68}
            cy={68}
            r={r}
            fill="none"
            stroke={color}
            strokeWidth={11}
            strokeDasharray={`${filled} ${circ}`}
            strokeLinecap="round"
          />
        </svg>
        <div className="absolute text-center" style={{ transform: "none" }}>
          <p className="text-2xl font-black leading-none" style={{ color }}>
            {pct}%
          </p>
          <p className="text-[10px] text-muted-foreground uppercase tracking-wider mt-0.5">
            Шийдвэр
          </p>
        </div>
      </div>
      <p className="text-xs text-muted-foreground text-center">
        <span className="font-semibold text-foreground">
          {Math.round((pct * total) / 100)}
        </span>{" "}
        / <span className="font-semibold text-foreground">{total}</span> эрсдэл
        шийдвэртэй
      </p>
    </div>
  );
}

// ─── Donut Chart ──────────────────────────────────────────────────────────────

function TreatmentDonut({
  counts,
  total,
}: {
  counts: Record<string, number>;
  total: number;
}) {
  const pieData = TREATMENT_CONFIG.map((t) => ({
    name: t.labelMn,
    value: counts[t.key] ?? 0,
    fill: t.hex,
  })).filter((d) => d.value > 0);

  return (
    <div className="flex flex-col sm:flex-row items-center gap-6">
      <div className="shrink-0">
        <PieChart width={200} height={200}>
          <Pie
            data={pieData}
            cx={100}
            cy={100}
            innerRadius={60}
            outerRadius={90}
            paddingAngle={3}
            dataKey="value"
            startAngle={90}
            endAngle={-270}
          >
            {pieData.map((entry, i) => (
              <Cell key={i} fill={entry.fill} strokeWidth={0} />
            ))}
          </Pie>
          <Tooltip
            formatter={(value) => {
              const n = Number(value);
              return [`${n} эрсдэл (${Math.round((n / total) * 100)}%)`];
            }}
            contentStyle={{
              fontSize: "11px",
              borderRadius: "8px",
              border: "1px solid hsl(var(--border))",
              background: "hsl(var(--background))",
              color: "hsl(var(--foreground))",
            }}
          />
        </PieChart>
      </div>

      <div className="flex flex-col gap-2.5 flex-1 min-w-0">
        {TREATMENT_CONFIG.map(({ key, labelMn, hex, textCls, Icon }) => {
          const count = counts[key] ?? 0;
          const pct = total > 0 ? Math.round((count / total) * 100) : 0;
          return (
            <div key={key} className="flex items-center gap-3">
              <div
                className="w-2.5 h-2.5 rounded-full shrink-0"
                style={{ background: hex }}
              />
              <div className="flex items-center gap-1.5 min-w-0 flex-1">
                {Icon && <Icon className={`w-3.5 h-3.5 shrink-0 ${textCls}`} />}
                <span className="text-sm text-muted-foreground truncate">
                  {labelMn}
                </span>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <div className="w-20 h-1.5 rounded-full bg-muted overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all"
                    style={{ width: `${pct}%`, background: hex }}
                  />
                </div>
                <span className="text-xs font-semibold w-6 text-right tabular-nums">
                  {count}
                </span>
                <span className="text-xs text-muted-foreground w-8 text-right tabular-nums">
                  {pct}%
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Risk Cards ───────────────────────────────────────────────────────────────

function controlStatusDot(status: string) {
  const s = (status ?? "").toLowerCase();
  if (s === "implemented" || s === "complete" || s === "completed")
    return "bg-emerald-500";
  if (s === "in_progress") return "bg-amber-500";
  return "bg-muted-foreground/40";
}

function controlStatusLabel(status: string) {
  const s = (status ?? "").toLowerCase();
  if (s === "implemented" || s === "complete" || s === "completed")
    return "Хэрэгжсэн";
  if (s === "in_progress") return "Хийгдэж буй";
  return "Эхлээгүй";
}

function controlStatusBadge(status: string) {
  const s = (status ?? "").toLowerCase();
  if (s === "implemented" || s === "complete" || s === "completed")
    return "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/20";
  if (s === "in_progress")
    return "bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-500/20";
  return "bg-muted text-muted-foreground border-border";
}

function RiskTable({ risks }: { risks: RiskRow[] }) {
  if (risks.length === 0) return null;
  return (
    <div className="space-y-3">
      {risks.map((r) => {
        const red = reductionPct(r.inherent_score, r.residual_risk_score);
        const owner = r.treatment_owner || r.department_control_owner;
        const residualKnown = r.residual_risk_score != null;
        return (
          <article
            key={r.risk_id}
            className="overflow-hidden rounded-xl border bg-card shadow-sm transition-colors hover:border-primary/25 hover:bg-muted/10 print:border-gray-300 print:shadow-none"
          >
            <div
              className={`h-1.5 bg-linear-to-r ${levelAccent(r.inherent_level)}`}
            />
            <div className="p-4">
              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div className="min-w-0 flex-1">
                  <div className="mb-2 flex flex-wrap items-center gap-2">
                    <Badge className="rounded-full border border-border bg-background px-2.5 py-0.5 text-[11px] font-semibold text-muted-foreground">
                      {r.nist_csf_category || r.nist_csf_function || "NIST"}
                    </Badge>
                    <Badge
                      className={`${levelStyle(r.inherent_level)} shrink-0 border px-2.5 py-0.5 text-[11px] font-bold`}
                    >
                      {r.inherent_score} · {levelLabel(r.inherent_level)}
                    </Badge>
                  </div>

                  <h3 className="line-clamp-2 text-base font-bold leading-snug">
                    {displayRiskTitle(r)}
                  </h3>
                  <p className="mt-1 line-clamp-1 text-sm text-muted-foreground">
                    {r.asset_name}
                    {r.asset_type ? ` · ${r.asset_type}` : ""}
                    {r.threat_name ? ` · ${r.threat_name}` : ""}
                  </p>
                </div>

                <div className="flex shrink-0 flex-wrap gap-2 lg:max-w-72 lg:justify-end">
                  <div className="inline-flex items-center gap-2 rounded-full border bg-background px-3 py-1.5 text-xs">
                    <UserRound className="h-3.5 w-3.5 text-muted-foreground" />
                    <span className="max-w-36 truncate font-semibold">
                      {owner || "Томилоогүй"}
                    </span>
                  </div>
                  {r.treatment_date && (
                    <div className="inline-flex items-center gap-2 rounded-full border bg-background px-3 py-1.5 text-xs text-muted-foreground">
                      <CalendarDays className="h-3.5 w-3.5" />
                      {new Date(r.treatment_date).toLocaleDateString("mn-MN", {
                        month: "short",
                        day: "numeric",
                      })}
                    </div>
                  )}
                </div>
              </div>

              <div className="mt-4 grid gap-3 lg:grid-cols-[1fr_10rem] lg:items-stretch">
                <div className="rounded-xl border bg-muted/20 p-3">
                  <div className="grid gap-2 sm:grid-cols-3">
                    <div className="rounded-lg bg-background p-3 ring-1 ring-border/70">
                      <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                        <Gauge className="h-3.5 w-3.5" />
                        Суурь
                      </div>
                      <p className="text-lg font-black text-rose-600">
                        {r.inherent_score}
                      </p>
                      <p className="text-xs font-semibold">
                        {levelLabel(r.inherent_level)}
                      </p>
                      <p className="mt-1 text-[11px] text-muted-foreground">
                        L{r.inherent_likelihood} x I{r.inherent_impact}
                      </p>
                    </div>

                    <div className="rounded-lg bg-background p-3 ring-1 ring-border/70">
                      <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                        <Shield className="h-3.5 w-3.5" />
                        Үлдэгдэл
                      </div>
                      <p
                        className={`text-lg font-black ${
                          residualKnown
                            ? "text-blue-600"
                            : "text-muted-foreground"
                        }`}
                      >
                        {residualKnown ? r.residual_risk_score : "—"}
                      </p>
                      <p className="text-xs font-semibold">
                        {residualKnown
                          ? levelLabel(r.residual_risk_level)
                          : "Тооцоогүй"}
                      </p>
                      <p className="mt-1 text-[11px] text-muted-foreground">
                        Хяналтын дараах оноо
                      </p>
                    </div>

                    <div className="rounded-lg bg-background p-3 ring-1 ring-border/70">
                      <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                        <TrendingDown className="h-3.5 w-3.5" />
                        Бууралт
                      </div>
                      <p className={`text-lg font-black ${reductionTone(red)}`}>
                        {red != null ? `${red}%` : "—"}
                      </p>
                      <p className="text-xs font-semibold">
                        {red != null ? "Эрсдэл буурсан" : "Хүлээгдэж байна"}
                      </p>
                      <p className="mt-1 text-[11px] text-muted-foreground">
                        Суурь → үлдэгдэл
                      </p>
                    </div>
                  </div>

                  <div className="mt-3">
                    <div className="mb-1 flex items-center justify-between text-[11px] text-muted-foreground">
                      <span>Бууралтын явц</span>
                      <span>{red != null ? `${red}%` : "0%"}</span>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full bg-muted">
                      <div
                        className="h-full rounded-full bg-linear-to-r from-emerald-500 to-teal-500"
                        style={{ width: reductionBarWidth(red) }}
                      />
                    </div>
                  </div>
                </div>

                <div className="rounded-xl border bg-muted/20 p-3">
                  <p className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                    Төлөв
                  </p>
                  <p className="mt-2 text-sm font-bold">
                    {residualKnown
                      ? "Үлдэгдэл эрсдэл тооцогдсон"
                      : "Үлдэгдэл оноо дутуу"}
                  </p>
                  <p className="mt-1 text-xs leading-5 text-muted-foreground">
                    {residualKnown
                      ? "Хяналтын үр нөлөө бүртгэгдсэн байна."
                      : "Хяналт сонгож хэрэгжилтийн төлөв оруулсны дараа оноо гарна."}
                  </p>
                </div>
              </div>

              {r.treatment_rationale && (
                <p className="mt-3 rounded-lg border bg-background px-3 py-2 text-sm leading-6 text-muted-foreground">
                  {r.treatment_rationale}
                </p>
              )}

              {r.selected_controls && r.selected_controls.length > 0 && (
                <div className="mt-3">
                  <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                    Хяналтын арга хэмжээ ({r.selected_controls.length})
                  </p>
                  <div className="grid gap-1.5 sm:grid-cols-2">
                    {r.selected_controls.map((ctrl, i) => (
                      <div
                        key={i}
                        className="flex items-center gap-2 rounded-lg border bg-background px-3 py-2 text-xs"
                      >
                        <span
                          className={`h-2 w-2 shrink-0 rounded-full ${controlStatusDot(ctrl.status)}`}
                        />
                        <span className="flex-1 truncate font-medium">
                          {ctrl.control_name}
                        </span>
                        <Badge
                          className={`shrink-0 border px-2 py-0 text-[10px] font-semibold ${controlStatusBadge(ctrl.status)}`}
                        >
                          {controlStatusLabel(ctrl.status)}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </article>
        );
      })}
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function RiskTreatmentReportPage() {
  const { user } = useAuth();
  const router = useRouter();
  const [data, setData] = useState<ReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!user) router.push("/auth/login");
  }, [user, router]);

  useEffect(() => {
    if (!user) return;
    fetch("/api/reports/risk-treatment")
      .then((r) => r.json())
      .then((d) => {
        if (d.error) throw new Error(d.error);
        setData(d);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [user]);

  if (!user) return null;

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-center space-y-3">
          <div className="inline-block w-8 h-8 border-4 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" />
          <p className="text-muted-foreground text-sm">
            Тайлан бэлтгэж байна...
          </p>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="p-8 text-center text-rose-600 space-y-2">
        <p className="font-semibold">Тайлан ачаалж чадсангүй</p>
        <p className="text-sm text-muted-foreground">{error}</p>
        <Button variant="outline" onClick={() => router.refresh()}>
          Дахин оролдох
        </Button>
      </div>
    );
  }

  const generatedDate = new Date(data.generated_at).toLocaleDateString(
    "mn-MN",
    {
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    },
  );

  return (
    <>
      <div className="bg-linear-to-br from-background to-muted/30 min-h-screen p-4 sm:p-8 pb-16">
        <div className="max-w-6xl mx-auto space-y-8">
          {/* ── Header + Export toolbar ──────────────────────────────── */}
          <div className="no-print space-y-4">
            <div>
              <h1 className="text-4xl font-bold mb-1">
                Эрсдэлийн арга хэмжээний тайлан
              </h1>
            </div>
            <div className="flex flex-wrap gap-3">
              {/* Risk Summary export */}
              <div className="flex items-center gap-2 rounded-lg border border-border bg-card px-4 py-2.5">
                <span className="text-sm font-medium mr-1">
                  Эрсдэлийн хураангуй
                </span>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => downloadRiskSummary("xls")}
                  className="gap-1.5 h-8"
                >
                  <Download className="w-3.5 h-3.5" />
                  Excel
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => downloadRiskSummary("csv")}
                  className="gap-1.5 h-8"
                >
                  <Download className="w-3.5 h-3.5" />
                  CSV
                </Button>
              </div>
              {/* Risk Treatment export */}
              <div className="flex items-center gap-2 rounded-lg border border-border bg-card px-4 py-2.5">
                <span className="text-sm font-medium mr-1">Арга хэмжээ</span>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => downloadRiskTreatment("xls")}
                  className="gap-1.5 h-8"
                >
                  <Download className="w-3.5 h-3.5" />
                  Excel
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => downloadRiskTreatment("csv")}
                  className="gap-1.5 h-8"
                >
                  <Download className="w-3.5 h-3.5" />
                  CSV
                </Button>
              </div>
            </div>
          </div>

          {/* ── Summary: coverage ring + treatment stat cards ─────────── */}
          <div className="grid gap-5 rounded-2xl border bg-card p-5 shadow-sm xl:grid-cols-[9.5rem_1fr]">
            <CoverageRing pct={data.coverage_pct} total={data.total} />
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
              {TREATMENT_CONFIG.map(
                ({ key, labelMn, Icon, hex, textCls, ringCls }) => {
                  const count = data.counts[key] ?? 0;
                  const isUntreated = key === "Untreated";
                  const value = isUntreated ? data.untreated : count;
                  return (
                    <div
                      key={key}
                      className={`flex min-h-30 flex-col justify-between rounded-xl ring-1 ${ringCls} p-4`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        {Icon && <Icon className={`w-4 h-4 ${textCls}`} />}
                        <span className="text-right text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                          {labelMn}
                        </span>
                      </div>
                      <p className={`text-3xl font-black ${textCls}`}>
                        {value}
                      </p>
                      <div className="h-1 rounded-full bg-muted overflow-hidden">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width:
                              data.total > 0
                                ? `${Math.round((value / data.total) * 100)}%`
                                : "0%",
                            background: hex,
                          }}
                        />
                      </div>
                      {isUntreated && (
                        <p className="text-[10px] text-muted-foreground">
                          шийдвэр шаардлагатай
                        </p>
                      )}
                    </div>
                  );
                },
              )}
            </div>
          </div>

          {/* ── Treatment distribution donut ─────────────────────────── */}
          {data.total > 0 && (
            <div className="rounded-2xl border bg-card p-6 shadow-sm space-y-4">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
                Арга хэмжээний шийдвэрийн тархалт
              </h2>
              <TreatmentDonut counts={data.counts} total={data.total} />
            </div>
          )}

          {data.total === 0 && (
            <div className="rounded-2xl border border-dashed bg-card p-10 text-center shadow-sm">
              <Shield className="mx-auto mb-3 h-8 w-8 text-muted-foreground" />
              <h2 className="text-lg font-bold">Эрсдэл бүртгэгдээгүй байна</h2>
              <p className="mx-auto mt-1 max-w-xl text-sm text-muted-foreground">
                Эрсдэлийн бүртгэл дээр бодит эрсдэл үүсгэсний дараа энэ тайлан
                арга хэмжээний шийдвэр, хариуцагч, үлдэгдэл оноо болон
                үндэслэлийг автоматаар харуулна.
              </p>
              <Button asChild className="mt-4">
                <Link href="/assessments">Эрсдэлийн бүртгэл нээх</Link>
              </Button>
            </div>
          )}

          {/* ── Level × Treatment matrix ─────────────────────────────── */}
          {data.total > 0 && (
            <div className="space-y-3">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
                Эрсдэлийн түвшин ба арга хэмжээний огтлолцол
              </h2>
              <div className="overflow-x-auto rounded-xl border print:border-gray-300">
                <table className="w-full text-sm">
                  <thead className="bg-muted/40 text-xs uppercase tracking-wider text-muted-foreground print:bg-gray-100">
                    <tr>
                      <th className="text-left font-semibold px-4 py-3">
                        Түвшин
                      </th>
                      {TREATMENT_CONFIG.map(({ key, labelMn }) => (
                        <th
                          key={key}
                          className="text-center font-semibold px-4 py-3"
                        >
                          {labelMn}
                        </th>
                      ))}
                      <th className="text-center font-semibold px-4 py-3">
                        Нийт
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {LEVELS.map((level) => {
                      const row = data.level_matrix[level] ?? {};
                      const rowTotal = Object.values(row).reduce(
                        (s, n) => s + n,
                        0,
                      );
                      return (
                        <tr
                          key={level}
                          className="border-t border-border/60 hover:bg-muted/20 print:border-gray-200"
                        >
                          <td className="px-4 py-3">
                            <Badge
                              className={`${levelStyle(level)} border font-semibold text-xs`}
                            >
                              {levelLabel(level)}
                            </Badge>
                          </td>
                          {TREATMENT_CONFIG.map(({ key }) => (
                            <td
                              key={key}
                              className="px-4 py-3 text-center font-mono text-sm"
                            >
                              {row[key] > 0 ? (
                                <span className="font-bold">{row[key]}</span>
                              ) : (
                                <span className="text-muted-foreground">—</span>
                              )}
                            </td>
                          ))}
                          <td className="px-4 py-3 text-center font-mono font-bold text-sm">
                            {rowTotal}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                  <tfoot>
                    <tr className="border-t-2 border-border bg-muted/30 print:border-gray-400 print:bg-gray-100">
                      <td className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                        Нийт
                      </td>
                      {TREATMENT_CONFIG.map(({ key }) => (
                        <td
                          key={key}
                          className="px-4 py-3 text-center font-mono font-bold"
                        >
                          {data.counts[key] ?? 0}
                        </td>
                      ))}
                      <td className="px-4 py-3 text-center font-mono font-black">
                        {data.total}
                      </td>
                    </tr>
                  </tfoot>
                </table>
              </div>
            </div>
          )}

          {/* ── Per-treatment sections ───────────────────────────────── */}
          {TREATMENT_CONFIG.map(
            ({
              key,
              labelMn,
              Icon,
              description,
              iconCls,
              badgeCls,
              headerCls,
            }) => {
              const risks = data.by_treatment[key] ?? [];
              if (risks.length === 0) return null;
              return (
                <div key={key} className="space-y-3 print-break-before">
                  <div
                    className={`flex items-start gap-3 rounded-xl border px-5 py-4 ${headerCls}`}
                  >
                    <div className="flex items-center gap-3 flex-1 min-w-0">
                      {Icon && (
                        <Icon className={`w-5 h-5 shrink-0 ${iconCls}`} />
                      )}
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <h2 className="text-base font-bold">{labelMn}</h2>
                          <Badge className={`${badgeCls} border font-semibold`}>
                            {risks.length} эрсдэл
                          </Badge>
                        </div>
                        <p className="text-xs text-muted-foreground mt-0.5">
                          {description}
                        </p>
                      </div>
                    </div>
                  </div>
                  <RiskTable risks={risks} />
                </div>
              );
            },
          )}

          {/* ── Footer ──────────────────────────────────────────────── */}
          <div className="border-t pt-6 text-xs text-muted-foreground text-center space-y-1">
            <p className="font-medium">
              NIST CSF 2.0 — Эрсдэлийн арга хэмжээний тайлан
            </p>
            <p>Үүсгэсэн: {generatedDate} · Нууц — Зөвхөн дотоод хэрэгцээнд</p>
          </div>
        </div>
      </div>
    </>
  );
}
