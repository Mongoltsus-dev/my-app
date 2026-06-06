"use client";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import {
  ArrowLeft,
  Boxes,
  ChevronDown,
  Filter,
  Layers,
  RefreshCw,
  Sparkles,
  Target,
  Upload,
} from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";

type Subcategory = {
  id: number;
  subcategory_id: string;
  nist_function: string;
  function_code: string | null;
  category_name: string | null;
  category_code: string | null;
  outcome_description: string | null;
  current_tier: number | null;
  target_tier: number | null;
  gap: number | null;
  risk_score: number | null;
  risk_level: string | null;
  primary_owner: string | null;
  stakeholders: string | null;
  tools: string | null;
  control_links: string | null;
  status: string | null;
  target_date: string | null;
};

type ApiResponse = {
  rows: Subcategory[];
  count: number;
  stats: {
    total?: number;
    critical_count?: number;
    high_count?: number;
    medium_count?: number;
    low_count?: number;
    avg_current_tier?: string;
    avg_target_tier?: string;
    subcategories_with_gap?: number;
  };
  by_function: Array<{
    nist_function: string;
    count: number;
    avg_current: string | null;
    avg_target: string | null;
    with_gap: number;
  }>;
};

const FUNCTION_ORDER = [
  "Govern",
  "Identify",
  "Protect",
  "Detect",
  "Respond",
  "Recover",
];

const FUNCTION_COLOR: Record<string, string> = {
  Govern: "from-purple-500 to-purple-600",
  Identify: "from-blue-500 to-blue-600",
  Protect: "from-emerald-500 to-emerald-600",
  Detect: "from-amber-500 to-amber-600",
  Respond: "from-orange-500 to-orange-600",
  Recover: "from-rose-500 to-rose-600",
};

const FUNCTION_MN: Record<string, string> = {
  Govern: "Засаглал",
  Identify: "Таних",
  Protect: "Хамгаалах",
  Detect: "Илрүүлэх",
  Respond: "Хариу үйлдэл",
  Recover: "Сэргээх",
};

const LEVEL_COLOR: Record<string, string> = {
  Critical: "bg-rose-100 text-rose-700 border-rose-200",
  High: "bg-orange-100 text-orange-700 border-orange-200",
  Medium: "bg-amber-100 text-amber-700 border-amber-200",
  Low: "bg-emerald-100 text-emerald-700 border-emerald-200",
};

function TierBar({
  current,
  target,
}: {
  current: number | null;
  target: number | null;
}) {
  const c = current ?? 0;
  const t = target ?? 0;
  return (
    <div className="flex items-center gap-2">
      <div className="flex w-32 gap-0.5">
        {[1, 2, 3, 4].map((tier) => (
          <div
            key={tier}
            className={`h-2 flex-1 rounded ${
              tier <= c
                ? "bg-emerald-500"
                : tier <= t
                  ? "bg-amber-300"
                  : "bg-slate-200 dark:bg-slate-800"
            }`}
            title={`Tier ${tier}`}
          />
        ))}
      </div>
      <span className="whitespace-nowrap text-[10px] font-medium text-muted-foreground">
        {c} → {t}
      </span>
    </div>
  );
}

export default function CsfProfilePage() {
  const [data, setData] = useState<ApiResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [filterFunction, setFilterFunction] = useState<string>("all");
  const [filterGapOnly, setFilterGapOnly] = useState(false);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [importing, setImporting] = useState(false);
  const [identifying, setIdentifying] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/csf-subcategories");
      if (r.ok) setData(await r.json());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const filtered = useMemo(() => {
    if (!data) return [];
    return data.rows.filter((r) => {
      if (filterFunction !== "all" && r.nist_function !== filterFunction)
        return false;
      if (filterGapOnly && (!r.gap || r.gap <= 0)) return false;
      return true;
    });
  }, [data, filterFunction, filterGapOnly]);

  // Group filtered rows by function → category
  const grouped = useMemo(() => {
    const out: Record<
      string,
      Record<string, { name: string; rows: Subcategory[] }>
    > = {};
    for (const r of filtered) {
      const fn = r.nist_function ?? "Other";
      const cat = r.category_code ?? "(uncategorised)";
      if (!out[fn]) out[fn] = {};
      if (!out[fn][cat])
        out[fn][cat] = { name: r.category_name ?? cat, rows: [] };
      out[fn][cat].rows.push(r);
    }
    return out;
  }, [filtered]);

  async function handleImport() {
    if (!importText.trim()) {
      setMessage("Paste your CSF assessment data first.");
      return;
    }
    setImporting(true);
    setMessage(null);
    try {
      const r = await fetch("/api/csf-subcategories/import", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ data: importText }),
      });
      const d = await r.json();
      if (r.ok) {
        setMessage(d.message ?? `Imported ${d.imported} rows.`);
        setImportOpen(false);
        setImportText("");
        await fetchData();
      } else {
        setMessage(`Error: ${d.error}`);
      }
    } finally {
      setImporting(false);
    }
  }

  async function handleIdentifyRisks() {
    if (
      !confirm(
        "Maturity gap бүхий NIST CSF subcategory-ууд дээр үндэслэн risk_register-д org-level эрсдэл үүсгэх үү? Давхар үүсэхгүй (subcategory_id-аар dedup).",
      )
    )
      return;
    setIdentifying(true);
    setMessage(null);
    try {
      const r = await fetch("/api/csf-subcategories/identify-risks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ min_gap: 1 }),
      });
      const d = await r.json();
      if (r.ok) {
        setMessage(
          `${d.created} шинэ эрсдэл үүсгэгдсэн, ${d.updated} шинэчлэгдсэн (${d.eligible_subcategories} тохирох subcategory).`,
        );
      } else {
        setMessage(`Error: ${d.error}`);
      }
    } finally {
      setIdentifying(false);
    }
  }

  return (
    <div className="flex h-full flex-col">
      {/* Header */}
      <div className="border-b bg-white px-6 py-4 dark:bg-slate-950">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Link
                href="/"
                className="flex items-center gap-1 hover:underline"
              >
                <ArrowLeft className="h-3 w-3" />
                Хяналтын самбар
              </Link>
            </div>
            <h1 className="mt-1 flex items-center gap-2 text-xl font-bold">
              <Layers className="h-5 w-5 text-blue-600" />
              NIST CSF 2.0 Profile (Subcategories)
            </h1>
            <p className="text-xs text-muted-foreground">
              Байгууллагын одоогийн төлөв (Current) болон зорилтот төлөв
              (Target)-ын зөрүүг NIST CSF 2.0-ийн бүх subcategory дээр харуулж,
              цоорхой дээр үндэслэн эрсдэл үүсгэнэ.
            </p>
          </div>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={fetchData}
              disabled={loading}
            >
              <RefreshCw
                className={`mr-1 h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`}
              />
              Шинэчлэх
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => setImportOpen(true)}
            >
              <Upload className="mr-1 h-3.5 w-3.5" />
              Импорт хийх
            </Button>
            <Button
              size="sm"
              onClick={handleIdentifyRisks}
              disabled={identifying || !data || data.count === 0}
            >
              <Sparkles
                className={`mr-1 h-3.5 w-3.5 ${identifying ? "animate-pulse" : ""}`}
              />
              {identifying ? "Үүсгэж байна..." : "Эрсдэл үүсгэх"}
            </Button>
            <Link href="/risk-register">
              <Button size="sm" variant="outline">
                <Boxes className="mr-1 h-3.5 w-3.5" />
                Эрсдэлийн бүртгэл
              </Button>
            </Link>
          </div>
        </div>

        {message && (
          <div className="mt-3 rounded border border-blue-200 bg-blue-50 px-3 py-1.5 text-xs text-blue-900 dark:border-blue-800 dark:bg-blue-950/40 dark:text-blue-200">
            {message}
          </div>
        )}

        {/* Summary stat cards */}
        {data && (
          <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
            <div className="rounded-lg border bg-slate-50 p-3 dark:bg-slate-900">
              <p className="text-[10px] font-bold uppercase tracking-wide text-slate-500">
                Нийт subcategory
              </p>
              <p className="mt-1 text-2xl font-bold">{data.stats.total ?? 0}</p>
              <p className="text-[10px] text-muted-foreground">
                {data.stats.subcategories_with_gap ?? 0} нь цоорхойтой
              </p>
            </div>
            <div className="rounded-lg border bg-rose-50 p-3 dark:bg-rose-950/30">
              <p className="text-[10px] font-bold uppercase tracking-wide text-rose-700">
                Ноцтой
              </p>
              <p className="mt-1 text-2xl font-bold text-rose-700">
                {data.stats.critical_count ?? 0}
              </p>
            </div>
            <div className="rounded-lg border bg-orange-50 p-3 dark:bg-orange-950/30">
              <p className="text-[10px] font-bold uppercase tracking-wide text-orange-700">
                Өндөр
              </p>
              <p className="mt-1 text-2xl font-bold text-orange-700">
                {data.stats.high_count ?? 0}
              </p>
            </div>
            <div className="rounded-lg border bg-amber-50 p-3 dark:bg-amber-950/30">
              <p className="text-[10px] font-bold uppercase tracking-wide text-amber-700">
                Дунд
              </p>
              <p className="mt-1 text-2xl font-bold text-amber-700">
                {data.stats.medium_count ?? 0}
              </p>
            </div>
            <div className="rounded-lg border bg-emerald-50 p-3 dark:bg-emerald-950/30">
              <p className="text-[10px] font-bold uppercase tracking-wide text-emerald-700">
                Бага
              </p>
              <p className="mt-1 text-2xl font-bold text-emerald-700">
                {data.stats.low_count ?? 0}
              </p>
            </div>
            <div className="rounded-lg border bg-blue-50 p-3 dark:bg-blue-950/30">
              <p className="text-[10px] font-bold uppercase tracking-wide text-blue-700">
                Дундаж tier
              </p>
              <p className="mt-1 text-2xl font-bold text-blue-700">
                {Number(data.stats.avg_current_tier ?? 0).toFixed(1)}
                <span className="text-sm text-blue-500">
                  /{Number(data.stats.avg_target_tier ?? 0).toFixed(1)}
                </span>
              </p>
              <p className="text-[10px] text-muted-foreground">
                Current / Target
              </p>
            </div>
          </div>
        )}

        {/* Function summary bar */}
        {data && data.by_function.length > 0 && (
          <div className="mt-3 grid gap-2 md:grid-cols-6">
            {FUNCTION_ORDER.map((fn) => {
              const f = data.by_function.find((x) => x.nist_function === fn);
              if (!f) return null;
              const active = filterFunction === fn;
              const pct = f.avg_target
                ? Math.round(
                    (Number(f.avg_current ?? 0) / Number(f.avg_target)) * 100,
                  )
                : 0;
              return (
                <button
                  key={fn}
                  onClick={() =>
                    setFilterFunction((v) => (v === fn ? "all" : fn))
                  }
                  className={`relative overflow-hidden rounded-lg border bg-white p-3 text-left text-xs shadow-sm transition-all dark:bg-slate-950 ${active ? "ring-2 ring-blue-500" : "hover:shadow-md"}`}
                >
                  <div
                    className={`absolute inset-x-0 top-0 h-1 bg-linear-to-r ${FUNCTION_COLOR[fn]}`}
                  />
                  <p className="font-bold">{fn}</p>
                  <p className="text-[10px] text-muted-foreground">
                    {FUNCTION_MN[fn]}
                  </p>
                  <div className="mt-2 flex items-end justify-between">
                    <div>
                      <p className="text-lg font-bold">{f.count}</p>
                      <p className="text-[10px] text-muted-foreground">
                        {f.with_gap} цоорхой
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="text-sm font-bold">{pct}%</p>
                      <p className="text-[10px] text-muted-foreground">
                        {Number(f.avg_current ?? 0).toFixed(1)} /{" "}
                        {Number(f.avg_target ?? 0).toFixed(1)}
                      </p>
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        )}

        {/* Filters */}
        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
          <Filter className="h-3 w-3 text-muted-foreground" />
          <button
            onClick={() => setFilterFunction("all")}
            className={`rounded px-2 py-1 ${filterFunction === "all" ? "bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-950" : "bg-slate-100 hover:bg-slate-200 dark:bg-slate-800"}`}
          >
            Бүх функц
          </button>
          {FUNCTION_ORDER.map((fn) => (
            <button
              key={fn}
              onClick={() => setFilterFunction((v) => (v === fn ? "all" : fn))}
              className={`rounded px-2 py-1 ${filterFunction === fn ? "bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-950" : "bg-slate-100 hover:bg-slate-200 dark:bg-slate-800"}`}
            >
              {fn}
            </button>
          ))}
          <label className="ml-2 flex cursor-pointer items-center gap-1 text-muted-foreground">
            <input
              type="checkbox"
              checked={filterGapOnly}
              onChange={(e) => setFilterGapOnly(e.target.checked)}
            />
            Зөвхөн цоорхойтой
          </label>
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-auto px-6 py-4">
        {loading ? (
          <div className="p-6 text-center text-muted-foreground">
            Уншиж байна...
          </div>
        ) : !data || data.count === 0 ? (
          <div className="rounded-lg border-2 border-dashed bg-white p-8 text-center dark:bg-slate-950">
            <Target className="mx-auto h-8 w-8 text-muted-foreground" />
            <p className="mt-2 text-sm font-semibold">
              NIST CSF subcategory импорт хийгээгүй байна
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              Өөрийн tab-delimited NIST CSF assessment файлаа &quot;Импорт
              хийх&quot; товчоор оруулна уу.
            </p>
            <Button
              className="mt-3"
              size="sm"
              onClick={() => setImportOpen(true)}
            >
              <Upload className="mr-1 h-3.5 w-3.5" />
              Эхэлж импорт хийх
            </Button>
          </div>
        ) : (
          <div className="space-y-4">
            {FUNCTION_ORDER.filter((fn) => grouped[fn]).map((fn) => {
              const categories = grouped[fn];
              const fnKey = `fn-${fn}`;
              const isCollapsed = collapsed[fnKey];
              return (
                <div
                  key={fn}
                  className="overflow-hidden rounded-lg border bg-white shadow-sm dark:bg-slate-950"
                >
                  <button
                    onClick={() =>
                      setCollapsed((s) => ({ ...s, [fnKey]: !s[fnKey] }))
                    }
                    className={`flex w-full items-center justify-between bg-linear-to-r px-4 py-2.5 text-left text-white ${FUNCTION_COLOR[fn]}`}
                  >
                    <div>
                      <p className="text-sm font-bold">
                        {fn}{" "}
                        <span className="opacity-80">· {FUNCTION_MN[fn]}</span>
                      </p>
                      <p className="text-[10px] opacity-90">
                        {Object.values(categories).reduce(
                          (sum, c) => sum + c.rows.length,
                          0,
                        )}{" "}
                        subcategory · {Object.keys(categories).length} category
                      </p>
                    </div>
                    <ChevronDown
                      className={`h-4 w-4 transition-transform ${isCollapsed ? "" : "rotate-180"}`}
                    />
                  </button>

                  {!isCollapsed &&
                    Object.entries(categories).map(([catCode, cat]) => (
                      <div key={catCode} className="border-t">
                        <div className="bg-slate-50 px-4 py-1.5 text-[11px] font-bold text-slate-700 dark:bg-slate-900 dark:text-slate-300">
                          {catCode} · {cat.name}
                        </div>
                        <table className="w-full text-xs">
                          <thead className="bg-slate-50/50 dark:bg-slate-900/40">
                            <tr className="text-left text-[10px] uppercase tracking-wide text-slate-500">
                              <th className="px-4 py-1.5 w-24">ID</th>
                              <th className="px-4 py-1.5">Outcome</th>
                              <th className="px-4 py-1.5 w-44">
                                Tier (Current → Target)
                              </th>
                              <th className="px-4 py-1.5 w-20 text-center">
                                Gap
                              </th>
                              <th className="px-4 py-1.5 w-24 text-center">
                                Risk
                              </th>
                              <th className="px-4 py-1.5 w-40">Owner</th>
                              <th className="px-4 py-1.5 w-20">Target</th>
                            </tr>
                          </thead>
                          <tbody>
                            {cat.rows.map((r) => (
                              <tr
                                key={r.subcategory_id}
                                className="border-t hover:bg-slate-50/40 dark:hover:bg-slate-900/40"
                              >
                                <td className="px-4 py-2 font-mono font-bold text-blue-700">
                                  {r.subcategory_id}
                                </td>
                                <td className="px-4 py-2">
                                  <p className="text-[11px] leading-snug">
                                    {r.outcome_description}
                                  </p>
                                  {r.control_links && (
                                    <p className="mt-0.5 text-[10px] text-muted-foreground">
                                      Controls: {r.control_links}
                                    </p>
                                  )}
                                </td>
                                <td className="px-4 py-2">
                                  <TierBar
                                    current={r.current_tier}
                                    target={r.target_tier}
                                  />
                                </td>
                                <td className="px-4 py-2 text-center">
                                  {r.gap && r.gap > 0 ? (
                                    <span className="inline-block rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-bold text-amber-700 dark:bg-amber-900/40 dark:text-amber-300">
                                      +{r.gap}
                                    </span>
                                  ) : (
                                    <span className="text-emerald-600">✓</span>
                                  )}
                                </td>
                                <td className="px-4 py-2 text-center">
                                  {r.risk_level ? (
                                    <span
                                      className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-bold ${LEVEL_COLOR[r.risk_level] ?? "bg-slate-100 text-slate-600"}`}
                                    >
                                      {r.risk_score ? `${r.risk_score} · ` : ""}
                                      {r.risk_level}
                                    </span>
                                  ) : (
                                    <span className="text-muted-foreground">
                                      —
                                    </span>
                                  )}
                                </td>
                                <td className="px-4 py-2 text-[11px]">
                                  {r.primary_owner ?? "—"}
                                </td>
                                <td className="px-4 py-2 text-[11px] text-muted-foreground">
                                  {r.target_date ?? "—"}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ))}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Import dialog */}
      <Dialog open={importOpen} onOpenChange={setImportOpen}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>NIST CSF 2.0 assessment-ийг импорт хийх</DialogTitle>
            <DialogDescription>
              Spreadsheet-ээсээ row-уудаа хуулж ND-ийн талбарт буулгана уу.
              Багана нь tab-delimited хэлбэртэй байх ёстой. Header мөр хуулж
              буусан ч асуудалгүй (автомат таних).
            </DialogDescription>
          </DialogHeader>
          <Textarea
            value={importText}
            onChange={(e) => setImportText(e.target.value)}
            placeholder="Govern&#9;GV&#9;Organizational Context&#9;GV.OC&#9;GV.OC-01&#9;The organizational mission ... &#9;2&#9;3&#9;1&#9;2&#9;Low&#9;CISO&#9;..."
            className="h-72 font-mono text-[11px]"
          />
          <p className="text-[11px] text-muted-foreground">
            Багануудын дараалал: Function, Func code, Category, Cat code, Subcat
            ID, Outcome, Current tier, Target tier, Gap, Risk score, Risk level,
            Primary owner, Stakeholders, Tools, Control links, Status, Target
            date.
          </p>
          <DialogFooter>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setImportOpen(false)}
              disabled={importing}
            >
              Болих
            </Button>
            <Button size="sm" onClick={handleImport} disabled={importing}>
              {importing ? "Импорт хийж байна..." : "Импорт хийх"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
