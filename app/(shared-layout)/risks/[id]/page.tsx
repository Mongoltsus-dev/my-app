"use client";

import { useAuth } from "@/app/context/AuthContext";
import {
  RISK_LEVEL_COLORS,
  RISK_LEVEL_LABELS,
  nistFunctionCode,
  nistFunctionLabel,
  normalizedScoreValue,
  riskOwnerLabel,
} from "@/lib/risk-display";
import {
  AlertTriangle,
  ArrowLeft,
  CalendarDays,
  CheckCircle2,
  Database,
  FileText,
  Save,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  TrendingDown,
  UserRound,
  XCircle,
} from "lucide-react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";

type Treatment = "Accept" | "Mitigate" | "Transfer" | null;

const ROLE_MANAGER = 2;
const MANAGEMENT_APPROVER_LABEL = "удирдлага";

interface RiskRow {
  id: number;
  risk_id: string;
  risk_code?: string | null;
  risk_title: string;
  risk_description: string | null;
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
  treatment_owner?: string | null;
  treatment_date?: string | null;
  risk_owner: string | null;
  department_control_owner?: string | null;
  assessed_by?: string | null;
  status: string | null;
}

interface NistControl {
  control_id: string;
  domain: string | null;
  control_name: string | null;
  description: string | null;
  nist_csf_function: string | null;
  nist_csf_category: string | null;
  implementation_effort?: string | null;
  priority: string | null;
  relevance?: number;
}

interface LinkedControlRecommendation {
  control_id: string | null;
  implementation_status: string | null;
}

const TREATMENT_CONFIG: Array<{
  value: Treatment;
  label: string;
  description: string;
  icon: React.ElementType;
  active: string;
}> = [
  {
    value: "Accept",
    label: "Хүлээж авах",
    description:
      "Эрсдэлийг одоогийн түвшинд хүлээн авч, удирдлагын зөвшөөрөл авна.",
    icon: CheckCircle2,
    active: "border-emerald-500 bg-emerald-50 text-emerald-800",
  },
  {
    value: "Mitigate",
    label: "Бууруулах",
    description:
      "Хяналт, арга хэмжээ хэрэгжүүлж эрсдэлийн магадлал эсвэл нөлөөллийг бууруулна.",
    icon: TrendingDown,
    active: "border-blue-500 bg-blue-50 text-blue-800",
  },
  {
    value: "Transfer",
    label: "Шилжүүлэх",
    description:
      "Даатгал, гэрээ эсвэл гуравдагч талын зохицуулалтаар эрсдэлийг шилжүүлнэ.",
    icon: ShieldOff,
    active: "border-amber-500 bg-amber-50 text-amber-800",
  },
];

const riskLevelLabel = (level: string | null | undefined) =>
  RISK_LEVEL_LABELS[level ?? ""] ?? level ?? "Тодорхойгүй";

const riskLevelColor = (level: string | null | undefined) =>
  RISK_LEVEL_COLORS[level ?? ""] ??
  "border-slate-200 bg-slate-50 text-slate-700 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-200";

function treatmentApprovalLabel(status: string | null | undefined) {
  if (status === "approved") return "Удирдлага баталсан";
  if (status === "rejected") return "Удирдлага буцаасан";
  if (status === "pending") return "Удирдлагын зөвшөөрөл хүлээгдэж байна";
  return "Удирдлагын зөвшөөрөл шаардлагатай";
}

function treatmentApprovalClass(status: string | null | undefined) {
  if (status === "approved") {
    return "border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-900/60 dark:bg-emerald-950/30 dark:text-emerald-200";
  }
  if (status === "rejected") {
    return "border-rose-200 bg-rose-50 text-rose-800 dark:border-rose-900/60 dark:bg-rose-950/30 dark:text-rose-200";
  }
  return "border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-200";
}

function shortDate(value: string | null | undefined) {
  if (!value) return "";
  return value.slice(0, 10);
}

function priorityLabel(value: string | null | undefined) {
  if (value === "Critical") return "Маш чухал";
  if (value === "High") return "Өндөр";
  if (value === "Medium") return "Дунд";
  if (value === "Low") return "Бага";
  return "Тодорхойгүй";
}

function priorityColor(value: string | null | undefined) {
  if (value === "Critical") {
    return "border-red-200 bg-red-50 text-red-700 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-300";
  }
  if (value === "High") {
    return "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-900/60 dark:bg-orange-950/30 dark:text-orange-300";
  }
  if (value === "Medium") {
    return "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-300";
  }
  return "border-slate-200 bg-slate-50 text-slate-700 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-200";
}

export default function RiskTreatmentPage() {
  const { user } = useAuth();
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const riskId = params.id;

  const [risk, setRisk] = useState<RiskRow | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [approvalSaving, setApprovalSaving] = useState(false);
  const [error, setError] = useState("");
  const [savedMessage, setSavedMessage] = useState("");
  const [selectedTreatment, setSelectedTreatment] = useState<Treatment>(null);
  const [rationale, setRationale] = useState("");
  const [owner, setOwner] = useState("");
  const [targetDate, setTargetDate] = useState("");
  const [applicableControls, setApplicableControls] = useState<NistControl[]>(
    [],
  );
  const [selectedControlIds, setSelectedControlIds] = useState<string[]>([]);
  const [controlsLoading, setControlsLoading] = useState(false);
  const [controlsError, setControlsError] = useState("");

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    fetch(`/api/risk-register?risk_id=${riskId}`)
      .then(async (response) => {
        if (!response.ok) throw new Error("Failed to fetch risk");
        const data = await response.json();
        const nextRisk = (data.risks?.[0] ?? null) as RiskRow | null;
        if (!mounted) return;
        if (!nextRisk) {
          setError("Эрсдэл олдсонгүй.");
          setRisk(null);
          return;
        }
        setRisk(nextRisk);
        setSelectedTreatment((nextRisk.risk_treatment as Treatment) ?? null);
        setRationale(nextRisk.treatment_rationale ?? "");
        setOwner(
          nextRisk.treatment_owner ||
            (riskOwnerLabel(nextRisk) === "-" ? "" : riskOwnerLabel(nextRisk)),
        );
        setTargetDate(shortDate(nextRisk.treatment_date));
        setError("");
      })
      .catch(() => {
        if (mounted) setError("Эрсдэлийн мэдээлэл ачаалах үед алдаа гарлаа.");
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });

    return () => {
      mounted = false;
    };
  }, [riskId]);

  useEffect(() => {
    if (!risk || selectedTreatment !== "Mitigate") {
      setControlsError("");
      return;
    }

    const riskId = risk.id;
    let mounted = true;
    setControlsLoading(true);
    setControlsError("");

    async function loadControls() {
      try {
        const controlsResponse = await fetch(
          `/api/controls/scf?risk_id=${riskId}`,
        );
        if (!controlsResponse.ok) {
          throw new Error("Failed to fetch controls");
        }

        const controlsData = await controlsResponse.json();
        const controls = (controlsData.controls ?? []) as NistControl[];
        const controlIds = new Set(
          controls.map((control) => control.control_id),
        );

        const existingResponse = await fetch(
          `/api/controls?risk_id=${riskId}`,
        ).catch(() => null);
        let implementedIds: string[] | null = null;

        if (existingResponse?.ok) {
          const existingData = await existingResponse.json();
          implementedIds = (
            (existingData.recommendations ??
              []) as LinkedControlRecommendation[]
          )
            .filter(
              (recommendation) =>
                recommendation.control_id &&
                recommendation.implementation_status === "existing",
            )
            .map((recommendation) => recommendation.control_id as string)
            .filter((controlId) => controlIds.has(controlId));
        }

        if (!mounted) return;
        setApplicableControls(controls);
        if (implementedIds) {
          setSelectedControlIds(implementedIds);
        } else {
          setSelectedControlIds((current) =>
            current.filter((controlId) => controlIds.has(controlId)),
          );
        }
      } catch {
        if (mounted) {
          setApplicableControls([]);
          setControlsError("Хамаарах хяналтуудыг ачаалах үед алдаа гарлаа.");
        }
      } finally {
        if (mounted) setControlsLoading(false);
      }
    }

    loadControls();

    return () => {
      mounted = false;
    };
  }, [risk, selectedTreatment]);

  const nistFn = useMemo(
    () => nistFunctionCode(risk?.nist_csf_function, risk?.nist_csf_category),
    [risk],
  );

  const inherentLikelihood = normalizedScoreValue(risk?.inherent_likelihood);
  const inherentImpact = normalizedScoreValue(risk?.inherent_impact);
  const canApproveTreatment = Number(user?.role ?? 0) === ROLE_MANAGER;
  const isSavedTreatmentSelected =
    Boolean(risk?.risk_treatment) && selectedTreatment === risk?.risk_treatment;
  const isTreatmentPending =
    isSavedTreatmentSelected &&
    risk?.risk_treatment_approval_status === "pending";

  const toggleControl = (controlId: string) => {
    setSelectedControlIds((current) =>
      current.includes(controlId)
        ? current.filter((id) => id !== controlId)
        : [...current, controlId],
    );
  };

  const saveTreatment = async () => {
    if (!risk || !selectedTreatment) return;
    setSaving(true);
    setSavedMessage("");
    try {
      const selectedControls =
        selectedTreatment === "Mitigate"
          ? applicableControls.filter((control) =>
              selectedControlIds.includes(control.control_id),
            )
          : [];
      const response = await fetch("/api/risk-register", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          risk_register_id: risk.id,
          risk_treatment: selectedTreatment,
          treatment_rationale: rationale,
          treatment_owner: owner,
          treatment_date: targetDate || null,
        }),
      });
      if (!response.ok) throw new Error("Failed to save treatment");

      if (selectedTreatment === "Mitigate" && selectedControls.length > 0) {
        const controlResponses = await Promise.all(
          selectedControls.map((control) =>
            fetch("/api/controls/select", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                risk_register_id: risk.id,
                control_id: control.control_id,
                control_name: control.control_name,
                nist_function: control.nist_csf_function,
                domain: control.domain,
                priority: control.priority,
                implementation_status: "existing",
              }),
            }),
          ),
        );
        if (controlResponses.some((controlResponse) => !controlResponse.ok)) {
          throw new Error("Failed to save selected controls");
        }
      }

      const data = await response.json();
      setRisk((current) =>
        current ? { ...current, ...(data.risk as Partial<RiskRow>) } : current,
      );
      setError("");
      const savedRisk = data.risk as Partial<RiskRow>;
      const approvalStatus = savedRisk.risk_treatment_approval_status;
      const controlMessage =
        selectedControls.length > 0
          ? `${selectedControls.length} хяналт хэрэгжүүлэхээр хадгаллаа. `
          : "";
      const approvalMessage =
        approvalStatus === "approved"
          ? "Удирдлагын баталгаажуулалт хадгалагдсан."
          : approvalStatus === "rejected"
            ? "Удирдлагын буцаасан төлөв хадгалагдсан."
            : "Удирдлагын баталгаажуулалт хүлээгдэж байна.";
      setSavedMessage(
        `${controlMessage}Арга хэмжээ хадгалагдлаа. ${approvalMessage}`,
      );
      router.push("/risks");
    } catch (saveError) {
      const message =
        saveError instanceof Error &&
        saveError.message === "Failed to save selected controls"
          ? "Сонгосон хяналтуудыг хадгалах үед алдаа гарлаа."
          : "Арга хэмжээ хадгалах үед алдаа гарлаа.";
      setError(message);
    } finally {
      setSaving(false);
    }
  };

  const reviewTreatment = async (approvalStatus: "approved" | "rejected") => {
    if (!risk || !risk.risk_treatment || !canApproveTreatment) return;

    setApprovalSaving(true);
    setSavedMessage("");
    setError("");
    try {
      const response = await fetch("/api/risk-register", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          risk_register_id: risk.id,
          risk_treatment_approval_status: approvalStatus,
        }),
      });
      if (!response.ok) throw new Error("Failed to review treatment");

      const data = await response.json();
      setRisk((current) =>
        current ? { ...current, ...(data.risk as Partial<RiskRow>) } : current,
      );
      setSavedMessage(
        approvalStatus === "approved"
          ? "Арга хэмжээний сонголтыг удирдлага баталлаа."
          : "Арга хэмжээний сонголтыг удирдлага буцаалаа.",
      );
    } catch {
      setError("Арга хэмжээний зөвшөөрөл хадгалах үед алдаа гарлаа.");
    } finally {
      setApprovalSaving(false);
    }
  };

  return (
    <div className="app-page p-4 pb-8 sm:p-6 md:p-8">
      <div className="mx-auto max-w-7xl space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <Link
            href="/risks"
            className="inline-flex h-9 items-center gap-2 rounded-md border border-border px-3 text-sm font-semibold text-muted-foreground transition hover:bg-accent hover:text-accent-foreground"
          >
            <ArrowLeft className="size-4" />
            Эрсдэлийн бүртгэл
          </Link>
        </div>

        {loading ? (
          <div className="h-120 animate-pulse rounded-2xl border border-border bg-muted/40" />
        ) : error && !risk ? (
          <div className="flex min-h-80 flex-col items-center justify-center rounded-2xl border border-border bg-card px-4 text-center text-muted-foreground">
            <AlertTriangle className="mb-3 size-10 text-orange-500" />
            <p className="text-sm">{error}</p>
          </div>
        ) : risk ? (
          <>
            <header className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-950">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-blue-600">
                    Эрсдэлийн арга хэмжээ
                  </p>
                  <h1 className="mt-2 text-2xl font-bold tracking-tight sm:text-3xl">
                    {risk.risk_title}
                  </h1>
                  <p className="mt-2 max-w-3xl text-sm text-muted-foreground">
                    Сонгосон эрсдэлийн мэдээллийг шалгаад тохирох арга хэмжээг
                    бүртгэнэ.
                  </p>
                </div>
                <span
                  className={`w-fit rounded-full border px-3 py-1 text-sm font-bold ${riskLevelColor(
                    risk.inherent_risk_level,
                  )}`}
                >
                  {risk.inherent_risk_score ?? "—"} ·{" "}
                  {riskLevelLabel(risk.inherent_risk_level)}
                </span>
              </div>
            </header>

            <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
              <section className="space-y-5">
                <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-950">
                  <h2 className="text-base font-bold">Эрсдэлийн мэдээлэл</h2>
                  <div className="mt-4 grid gap-3 md:grid-cols-2">
                    {[
                      {
                        label: "Хөрөнгө",
                        value: risk.asset_name ?? "Хамаарахгүй",
                        sub: risk.asset_type,
                        icon: Database,
                      },
                      {
                        label: "Аюул",
                        value: risk.threat_name ?? "Тодорхойгүй",
                        sub: risk.threat_category,
                        icon: ShieldAlert,
                      },
                      {
                        label: "Хариуцагч",
                        value: riskOwnerLabel(risk),
                        sub: risk.status ? `Төлөв: ${risk.status}` : null,
                        icon: UserRound,
                      },
                      {
                        label: "NIST CSF",
                        value:
                          risk.nist_csf_category ||
                          risk.nist_csf_function ||
                          "Тодорхойгүй",
                        sub: nistFn ? nistFunctionLabel(nistFn) : null,
                        icon: ShieldCheck,
                      },
                    ].map(({ label, value, sub, icon: Icon }) => (
                      <div
                        key={label}
                        className="rounded-xl border border-slate-200 bg-slate-50/70 p-4 dark:border-slate-800 dark:bg-slate-900/30"
                      >
                        <div className="flex items-start gap-3">
                          <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-white text-blue-600 shadow-sm dark:bg-slate-950">
                            <Icon className="size-4" />
                          </span>
                          <div className="min-w-0">
                            <p className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                              {label}
                            </p>
                            <p className="mt-1 truncate text-sm font-semibold">
                              {value}
                            </p>
                            {sub && (
                              <p className="mt-0.5 truncate text-xs text-muted-foreground">
                                {sub}
                              </p>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-950">
                  <h2 className="text-base font-bold">Оноо ба түвшин</h2>
                  <div className="mt-4 grid gap-3 md:grid-cols-2">
                    <div className="rounded-xl border border-slate-200 p-4 dark:border-slate-800">
                      <p className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                        Анхны эрсдэл
                      </p>
                      <p className="mt-2 text-2xl font-black">
                        {risk.inherent_risk_score ?? "—"}
                      </p>
                      <p className="mt-1 text-sm text-muted-foreground">
                        {riskLevelLabel(risk.inherent_risk_level)} · Маг.{" "}
                        {inherentLikelihood ?? "—"} · Нөл.{" "}
                        {inherentImpact ?? "—"}
                      </p>
                    </div>
                    <div className="rounded-xl border border-slate-200 p-4 dark:border-slate-800">
                      <p className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                        Үлдэгдэл эрсдэл
                      </p>
                      <p className="mt-2 text-2xl font-black">
                        {risk.residual_risk_score ?? "—"}
                      </p>
                      <p className="mt-1 text-sm text-muted-foreground">
                        {risk.residual_risk_level
                          ? riskLevelLabel(risk.residual_risk_level)
                          : "Одоогоор тооцоогүй"}
                      </p>
                    </div>
                  </div>
                </div>

                <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-950">
                  <div className="flex items-center gap-2">
                    <FileText className="size-4 text-blue-600" />
                    <h2 className="text-base font-bold">Тайлбар</h2>
                  </div>
                  <p className="mt-3 text-sm leading-6 text-slate-700 dark:text-slate-300">
                    {risk.risk_description ||
                      "Энэ эрсдэлд тайлбар бүртгэгдээгүй байна."}
                  </p>

                  {selectedTreatment === "Mitigate" && (
                    <div className="mt-5 border-t border-slate-200 pt-5 dark:border-slate-800">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div>
                          <h3 className="text-sm font-bold">
                            Хэрэгжүүлэх хяналтууд
                          </h3>
                          <p className="mt-1 text-xs leading-5 text-muted-foreground">
                            Энэ эрсдэлийг бууруулахад тохирох хяналтаа сонгоно
                            уу. Сонгосон хяналтууд хадгалах үед хэрэгжсэнээр
                            бүртгэгдэнэ.
                          </p>
                        </div>
                        {!controlsLoading && (
                          <span className="rounded-full bg-blue-50 px-3 py-1 text-xs font-bold text-blue-700 dark:bg-blue-950/40 dark:text-blue-300">
                            {selectedControlIds.length} сонгосон
                          </span>
                        )}
                      </div>

                      <div className="mt-4 max-h-107.5 space-y-2 overflow-y-auto pr-1">
                        {controlsLoading ? (
                          <>
                            <div className="h-24 animate-pulse rounded-xl bg-slate-100 dark:bg-slate-900" />
                            <div className="h-24 animate-pulse rounded-xl bg-slate-100 dark:bg-slate-900" />
                            <div className="h-24 animate-pulse rounded-xl bg-slate-100 dark:bg-slate-900" />
                          </>
                        ) : controlsError ? (
                          <p className="rounded-xl border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-300">
                            {controlsError}
                          </p>
                        ) : applicableControls.length === 0 ? (
                          <p className="rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm text-muted-foreground dark:border-slate-800 dark:bg-slate-900/40">
                            Энэ эрсдэлд шууд тохирох хяналт олдсонгүй.
                          </p>
                        ) : (
                          applicableControls.map((control) => {
                            const isSelected = selectedControlIds.includes(
                              control.control_id,
                            );
                            return (
                              <button
                                key={control.control_id}
                                type="button"
                                onClick={() =>
                                  toggleControl(control.control_id)
                                }
                                className={`flex w-full items-start gap-3 rounded-xl border p-3 text-left transition hover:border-blue-300 hover:bg-blue-50/50 dark:hover:bg-blue-950/20 ${
                                  isSelected
                                    ? "border-blue-500 bg-blue-50 shadow-sm ring-1 ring-blue-500/20 dark:border-blue-500 dark:bg-blue-950/25"
                                    : "border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-950"
                                }`}
                              >
                                <span
                                  className={`mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-md border ${
                                    isSelected
                                      ? "border-blue-600 bg-blue-600 text-white"
                                      : "border-slate-300 bg-white text-transparent dark:border-slate-700 dark:bg-slate-950"
                                  }`}
                                >
                                  <CheckCircle2 className="size-4" />
                                </span>
                                <span className="min-w-0 flex-1">
                                  <span className="flex flex-wrap items-center gap-1.5">
                                    <span className="rounded-md bg-slate-100 px-2 py-0.5 text-[11px] font-bold text-slate-700 dark:bg-slate-900 dark:text-slate-200">
                                      {control.control_id}
                                    </span>
                                    {control.priority && (
                                      <span
                                        className={`rounded-full border px-2 py-0.5 text-[10px] font-bold ${priorityColor(control.priority)}`}
                                      >
                                        {priorityLabel(control.priority)}
                                      </span>
                                    )}
                                    {isSelected && (
                                      <span className="rounded-full bg-blue-600 px-2 py-0.5 text-[10px] font-bold text-white">
                                        Хэрэгжүүлнэ
                                      </span>
                                    )}
                                  </span>
                                  <span className="mt-1 block text-sm font-bold leading-tight">
                                    {control.control_name ?? "Нэргүй хяналт"}
                                  </span>
                                  {control.description && (
                                    <span className="mt-1 line-clamp-2 block text-xs leading-5 text-muted-foreground">
                                      {control.description}
                                    </span>
                                  )}
                                  <span className="mt-2 flex flex-wrap gap-1.5 text-[11px] text-muted-foreground">
                                    {control.domain && (
                                      <span className="rounded-md bg-slate-100 px-2 py-0.5 dark:bg-slate-900">
                                        {control.domain}
                                      </span>
                                    )}
                                    {control.nist_csf_category && (
                                      <span className="rounded-md bg-slate-100 px-2 py-0.5 dark:bg-slate-900">
                                        {control.nist_csf_category}
                                      </span>
                                    )}
                                  </span>
                                </span>
                              </button>
                            );
                          })
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </section>

              <aside className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-950 xl:sticky xl:top-4">
                <h2 className="text-base font-bold">Арга хэмжээ авах</h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  Эрсдэлийг хэрхэн удирдах шийдвэрээ сонгоно уу.
                </p>

                <div className="mt-4 space-y-2">
                  {TREATMENT_CONFIG.map((item) => {
                    const Icon = item.icon;
                    const isActive = selectedTreatment === item.value;
                    return (
                      <button
                        key={item.value}
                        type="button"
                        onClick={() => setSelectedTreatment(item.value)}
                        className={`flex w-full items-start gap-3 rounded-xl border p-3 text-left transition hover:border-blue-300 hover:bg-blue-50/40 dark:hover:bg-blue-950/20 ${
                          isActive
                            ? item.active
                            : "border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-950"
                        }`}
                      >
                        <Icon className="mt-0.5 size-5 shrink-0" />
                        <span className="min-w-0 flex-1">
                          <span className="block text-sm font-bold">
                            {item.label}
                          </span>
                          <span className="mt-1 block text-xs leading-5 text-muted-foreground">
                            {item.description}
                          </span>
                        </span>
                        {isActive && <CheckCircle2 className="size-4" />}
                      </button>
                    );
                  })}
                </div>

                <label className="mt-4 block">
                  <span className="text-xs font-semibold">Хариуцагч</span>
                  <input
                    value={owner}
                    onChange={(event) => setOwner(event.target.value)}
                    placeholder="Хариуцагчийн нэр, албан тушаал"
                    className="app-form-field mt-1 h-10 w-full rounded-md border px-3 text-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
                  />
                </label>

                <label className="mt-3 block">
                  <span className="text-xs font-semibold">Зорилтот огноо</span>
                  <div className="relative mt-1">
                    <CalendarDays className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                    <input
                      type="date"
                      value={targetDate}
                      onChange={(event) => setTargetDate(event.target.value)}
                      className="app-form-field h-10 w-full rounded-md border pl-9 pr-3 text-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
                    />
                  </div>
                </label>

                <label className="mt-3 block">
                  <span className="text-xs font-semibold">
                    Арга хэмжээний тэмдэглэл
                  </span>
                  <textarea
                    value={rationale}
                    onChange={(event) => setRationale(event.target.value)}
                    rows={4}
                    placeholder="Хэрэгжүүлэх арга хэмжээ, нотолгоо, шийдвэрийн үндэслэлийг бичнэ үү..."
                    className="app-form-field mt-1 w-full rounded-md border px-3 py-2 text-sm leading-6 outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
                  />
                </label>

                {selectedTreatment && (
                  <div
                    className={`mt-4 rounded-xl border p-3 text-xs leading-5 ${
                      isSavedTreatmentSelected
                        ? treatmentApprovalClass(
                            risk.risk_treatment_approval_status,
                          )
                        : "border-slate-200 bg-slate-50 text-slate-700 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-200"
                    }`}
                  >
                    <div className="flex items-start gap-2">
                      <ShieldCheck className="mt-0.5 size-4 shrink-0" />
                      <div className="min-w-0 flex-1">
                        <p className="font-bold">
                          {isSavedTreatmentSelected
                            ? treatmentApprovalLabel(
                                risk.risk_treatment_approval_status,
                              )
                            : "Өөрчлөлт хадгалагдаагүй"}
                        </p>
                        {isSavedTreatmentSelected &&
                          risk.risk_treatment_approval_status ===
                            "approved" &&
                          risk.risk_treatment_approved_at && (
                            <p className="mt-1 font-medium">
                              Баталсан: {MANAGEMENT_APPROVER_LABEL} ·{" "}
                              {new Date(
                                risk.risk_treatment_approved_at,
                              ).toLocaleDateString("mn-MN")}
                            </p>
                          )}
                      </div>
                    </div>

                    {canApproveTreatment && isTreatmentPending && (
                      <div className="mt-3 grid grid-cols-2 gap-2">
                        <button
                          type="button"
                          onClick={() => reviewTreatment("rejected")}
                          disabled={approvalSaving}
                          className="inline-flex h-9 items-center justify-center gap-1.5 rounded-md border border-rose-200 bg-white px-3 text-xs font-bold text-rose-700 transition hover:bg-rose-50 disabled:pointer-events-none disabled:opacity-50 dark:border-rose-900 dark:bg-slate-950 dark:text-rose-300 dark:hover:bg-rose-950/30"
                        >
                          <XCircle className="size-4" />
                          Буцаах
                        </button>
                        <button
                          type="button"
                          onClick={() => reviewTreatment("approved")}
                          disabled={approvalSaving}
                          className="inline-flex h-9 items-center justify-center gap-1.5 rounded-md bg-emerald-600 px-3 text-xs font-bold text-white transition hover:bg-emerald-700 disabled:pointer-events-none disabled:opacity-50"
                        >
                          <CheckCircle2 className="size-4" />
                          Батлах
                        </button>
                      </div>
                    )}
                  </div>
                )}

                {error && (
                  <p className="mt-4 text-sm font-medium text-red-600">
                    {error}
                  </p>
                )}
                {savedMessage && (
                  <p className="mt-4 text-sm font-medium text-emerald-600">
                    {savedMessage}
                  </p>
                )}

                <button
                  type="button"
                  onClick={saveTreatment}
                  disabled={!selectedTreatment || saving}
                  className="mt-5 inline-flex h-11 w-full items-center justify-center gap-2 rounded-md bg-blue-600 px-4 text-sm font-bold text-white shadow-sm transition hover:bg-blue-700 disabled:pointer-events-none disabled:opacity-50"
                >
                  <Save className="size-4" />
                  {saving ? "Хадгалж байна..." : "Арга хэмжээ хадгалах"}
                </button>
              </aside>
            </div>
          </>
        ) : null}
      </div>
    </div>
  );
}
