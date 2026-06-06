// Shared display helpers for NIST CSF functions and risk levels.
//
// Pure module (no DB / React imports) so it can be imported from the client
// risks pages. Previously these maps and helpers were copy-pasted between
// app/(shared-layout)/risks/page.tsx and risks/[id]/page.tsx; keep them here so
// a label or alias only ever has to change in one place.

export const RISK_LEVEL_LABELS: Record<string, string> = {
  Critical: "Ноцтой",
  High: "Өндөр",
  Medium: "Дунд",
  Low: "Бага",
};

export const RISK_LEVEL_COLORS: Record<string, string> = {
  Critical:
    "border-red-200 bg-red-50 text-red-700 dark:border-red-900/70 dark:bg-red-950/40 dark:text-red-300",
  High: "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-900/70 dark:bg-orange-950/40 dark:text-orange-300",
  Medium:
    "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900/70 dark:bg-amber-950/40 dark:text-amber-300",
  Low: "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900/70 dark:bg-emerald-950/40 dark:text-emerald-300",
};

export const NIST_FUNCTION_ORDER = ["GV", "ID", "PR", "DE", "RS", "RC"];

export const NIST_FUNCTION_LABELS: Record<string, string> = {
  GV: "Засаглал",
  ID: "Таних",
  PR: "Хамгаалах",
  DE: "Илрүүлэх",
  RS: "Хариу арга хэмжээ",
  RC: "Сэргээх",
};

export const NIST_FUNCTION_ALIASES: Record<string, string> = {
  GOVERN: "GV",
  IDENTIFY: "ID",
  PROTECT: "PR",
  DETECT: "DE",
  RESPOND: "RS",
  RECOVER: "RC",
  ЗАСАГЛАЛ: "GV",
  ТАНИХ: "ID",
  ХАМГААЛАХ: "PR",
  ИЛРҮҮЛЭХ: "DE",
  "ХАРИУ АРГА ХЭМЖЭЭ": "RS",
  "ХАРИУ ҮЙЛДЭЛ": "RS",
  СЭРГЭЭХ: "RC",
};

// Resolve a NIST CSF function code ("PR") from a free-form value that may be a
// category code ("PR.AA"), a full name ("Protect"), or a Mongolian label.
export const nistFunctionCode = (
  value: string | null | undefined,
  fallback?: string | null,
) => {
  for (const candidate of [fallback, value]) {
    const raw = (candidate || "").trim();
    if (!raw) continue;

    const prefix = raw.split(/[.\s-]/)[0].toUpperCase();
    if (NIST_FUNCTION_LABELS[prefix]) return prefix;

    const alias = NIST_FUNCTION_ALIASES[raw.toUpperCase()];
    if (alias) return alias;
  }

  return "";
};

export const nistFunctionLabel = (code: string) =>
  NIST_FUNCTION_LABELS[code] ?? code;

// Coerce a likelihood/impact value to an integer in the 1–5 range, or null.
export const normalizedScoreValue = (
  value: number | string | null | undefined,
) => {
  const numberValue = Number(value);
  if (!Number.isFinite(numberValue)) return null;
  const rounded = Math.round(numberValue);
  return rounded >= 1 && rounded <= 5 ? rounded : null;
};

export type RiskOwnerFields = {
  risk_owner?: string | null;
  department_control_owner?: string | null;
  treatment_owner?: string | null;
};

export const riskOwnerLabel = (risk: RiskOwnerFields) =>
  risk.risk_owner || risk.department_control_owner || risk.treatment_owner || "-";
