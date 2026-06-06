import { NextResponse } from "next/server";

type ExportFormat = "csv" | "xls";
type ExportRow = Record<string, unknown>;

const MIME_TYPES: Record<ExportFormat, string> = {
  csv: "text/csv; charset=utf-8",
  xls: "application/vnd.ms-excel; charset=utf-8",
};

// ─── Column widths (pixels) ───────────────────────────────────────────────────

const COLUMN_WIDTHS: Record<string, number> = {
  "Risk Code": 90,
  "Risk Title": 280,
  Asset: 160,
  "Asset Code": 90,
  "Asset Type": 110,
  "Asset Criticality": 110,
  Criticality: 90,
  Threat: 140,
  "NIST Function": 90,
  "NIST Category": 90,
  "NIST CSF Function": 100,
  "NIST CSF Category": 100,
  Likelihood: 80,
  Impact: 80,
  "Risk Score": 80,
  "Inherent Score": 80,
  "Risk Level": 90,
  "Inherent Level": 90,
  "Residual Score": 90,
  "Residual Level": 90,
  "Risk Reduction": 90,
  Treatment: 110,
  "Treatment Owner": 130,
  "Treatment Date": 110,
  "Management Approval": 130,
  "Approved By": 120,
  "Approved At": 120,
  Rationale: 230,
  Status: 90,
  "Selected Controls": 260,
  Owner: 130,
  Location: 130,
  "Business Owner": 140,
  "Technical Owner": 140,
  Classification: 110,
  "RTO Hours": 80,
  "RPO Hours": 80,
  "Risk Count": 80,
  "Highest Risk Score": 110,
  "Average Risk Score": 110,
  "Open Vulnerabilities": 120,
  "Mapped Risks": 90,
  "Recommended Controls": 130,
  "Implemented Controls": 130,
  "Implementation Rate": 120,
};

const COLUMN_LABELS_MN: Record<string, string> = {
  "Risk Code": "Эрсдэлийн код",
  "Risk Title": "Эрсдэлийн нэр",
  Asset: "Хөрөнгө",
  "Asset Code": "Хөрөнгийн код",
  "Asset Type": "Хөрөнгийн төрөл",
  "Asset Criticality": "Хөрөнгийн чухал түвшин",
  Criticality: "Чухал түвшин",
  Threat: "Аюул",
  "NIST Function": "NIST функц",
  "NIST Category": "NIST ангилал",
  "NIST CSF Function": "NIST CSF функц",
  "NIST CSF Category": "NIST CSF ангилал",
  Likelihood: "Магадлал",
  Impact: "Нөлөөлөл",
  "Risk Score": "Эрсдэлийн оноо",
  "Inherent Score": "Анхны оноо",
  "Risk Level": "Эрсдэлийн түвшин",
  "Inherent Level": "Анхны түвшин",
  "Residual Score": "Үлдэгдэл оноо",
  "Residual Level": "Үлдэгдэл түвшин",
  "Risk Reduction": "Эрсдэлийн бууралт",
  Treatment: "Арга хэмжээ",
  "Treatment Owner": "Арга хэмжээний хариуцагч",
  "Treatment Date": "Арга хэмжээний огноо",
  "Management Approval": "Удирдлагын баталгаа",
  "Approved By": "Баталсан хүн",
  "Approved At": "Баталсан огноо",
  Rationale: "Үндэслэл",
  Status: "Төлөв",
  "Selected Controls": "Сонгосон хяналтууд",
  Owner: "Хариуцагч",
  Location: "Байршил",
  "Business Owner": "Бизнес хариуцагч",
  "Technical Owner": "Техник хариуцагч",
  Classification: "Ангилал",
  "RTO Hours": "RTO цаг",
  "RPO Hours": "RPO цаг",
  "Risk Count": "Эрсдэлийн тоо",
  "Highest Risk Score": "Хамгийн өндөр эрсдэлийн оноо",
  "Average Risk Score": "Дундаж эрсдэлийн оноо",
  "Open Vulnerabilities": "Нээлттэй эмзэг байдал",
  "Mapped Risks": "Холбогдсон эрсдэлүүд",
  "Recommended Controls": "Санал болгосон хяналтууд",
  "Implemented Controls": "Хэрэгжсэн хяналтууд",
  "Implementation Rate": "Хэрэгжилтийн хувь",
  Message: "Мэдээлэл",
};

const RISK_LEVEL_LABELS_MN: Record<string, string> = {
  critical: "Ноцтой",
  high: "Өндөр",
  medium: "Дунд",
  low: "Бага",
  unknown: "Тодорхойгүй",
};

const TREATMENT_LABELS_MN: Record<string, string> = {
  treat: "Бууруулах",
  mitigate: "Бууруулах",
  reduce: "Бууруулах",
  transfer: "Шилжүүлэх",
  tolerate: "Хүлээн зөвшөөрөх",
  accept: "Хүлээн зөвшөөрөх",
  terminate: "Зогсоох",
  avoid: "Зогсоох",
  untreated: "Шийдвэрлээгүй",
};

const STATUS_LABELS_MN: Record<string, string> = {
  pending: "Хүлээгдэж байна",
  approved: "Батлагдсан",
  rejected: "Татгалзсан",
  open: "Нээлттэй",
  closed: "Хаагдсан",
  active: "Идэвхтэй",
  inactive: "Идэвхгүй",
  implemented: "Хэрэгжсэн",
  complete: "Дууссан",
  completed: "Дууссан",
  in_progress: "Хийгдэж байна",
  "in progress": "Хийгдэж байна",
  "not started": "Эхлээгүй",
  not_started: "Эхлээгүй",
  remediated: "Засварласан",
  false_positive: "Хуурамч эерэг",
};

const NIST_FUNCTION_LABELS_MN: Record<string, string> = {
  govern: "Засаглал",
  identify: "Тодорхойлох",
  protect: "Хамгаалах",
  detect: "Илрүүлэх",
  respond: "Хариу арга хэмжээ",
  recover: "Сэргээх",
};

const REPORT_FILENAME_PARTS: Record<string, string> = {
  "Эрсдэлийн хураангуй": "ersdeliin-huraangui",
  "Хөрөнгийн эрсдэл": "hurungiin-ersdel",
  "NIST CSF нийцэл": "nist-csf-niitsel",
  "Эрсдэлийн арга хэмжээ": "ersdeliin-arga-hemjee",
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function normalizeFormat(value: string | null): ExportFormat {
  return value === "xls" || value === "excel" ? "xls" : "csv";
}

function safeFilePart(value: string) {
  const localizedName = REPORT_FILENAME_PARTS[value];
  if (localizedName) return localizedName;

  return (
    value
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/(^-|-$)/g, "") || "report"
  );
}

function displayValue(value: unknown): string {
  if (value === undefined || value === null) return "";
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function columnLabel(column: string) {
  return COLUMN_LABELS_MN[column] ?? column;
}

function localizeMappedValue(
  value: string,
  labels: Record<string, string>,
) {
  return labels[value.trim().toLowerCase()] ?? value;
}

function localizeCellValue(column: string, value: string) {
  const col = column.toLowerCase();
  if (value === "") return value;

  if (col.includes("level") || col === "criticality" || col === "asset criticality") {
    return localizeMappedValue(value, RISK_LEVEL_LABELS_MN);
  }

  if (col === "treatment") {
    return localizeMappedValue(value, TREATMENT_LABELS_MN);
  }

  if (
    col === "status" ||
    col === "management approval" ||
    col === "implementation status"
  ) {
    return localizeMappedValue(value, STATUS_LABELS_MN);
  }

  if (col === "nist function" || col === "nist csf function") {
    return localizeMappedValue(value, NIST_FUNCTION_LABELS_MN);
  }

  return value;
}

function escapeCsvValue(value: unknown) {
  const text = displayValue(value);
  if (!/[",\r\n]/.test(text)) return text;
  return `"${text.replaceAll('"', '""')}"`;
}

function escapeHtml(value: unknown) {
  return displayValue(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

/** Format the display value for a cell based on its column name */
function formatCellValue(column: string, value: unknown): string {
  const col = column.toLowerCase();
  const raw = displayValue(value);

  // Append % to Implementation Rate
  if (col === "implementation rate" && raw !== "" && raw !== "0") {
    return `${raw}%`;
  }

  // Show dash for zero scores / likelihoods / impacts
  if (
    (col.includes("score") || col === "likelihood" || col === "impact") &&
    raw === "0"
  ) {
    return "—";
  }

  return localizeCellValue(column, raw);
}

/** Return the CSS class to apply to a <td> based on column + value */
function getCellClass(column: string, value: unknown): string {
  const col = column.toLowerCase();
  const val = displayValue(value).toLowerCase().trim();

  // Risk / inherent / residual level
  if (col.includes("level")) {
    if (val === "critical") return "lv-critical";
    if (val === "high") return "lv-high";
    if (val === "medium") return "lv-medium";
    if (val === "low") return "lv-low";
  }

  // Numeric risk/inherent score (not residual)
  if (col === "risk score" || col === "inherent score") {
    const n = Number(value);
    if (!isNaN(n) && n > 0) {
      if (n >= 17) return "sc-critical";
      if (n >= 10) return "sc-high";
      if (n >= 5) return "sc-medium";
      return "sc-low";
    }
  }

  // Residual score
  if (col === "residual score") {
    const n = Number(value);
    if (!isNaN(n) && n > 0) {
      if (n >= 17) return "sc-critical";
      if (n >= 10) return "sc-high";
      if (n >= 5) return "sc-medium";
      return "sc-low";
    }
  }

  // Treatment
  if (col === "treatment") {
    if (val === "treat") return "tr-treat";
    if (val === "transfer") return "tr-transfer";
    if (val === "tolerate") return "tr-tolerate";
    if (val === "terminate") return "tr-terminate";
    if (val === "untreated" || val === "") return "tr-untreated";
  }

  // Implementation rate
  if (col === "implementation rate") {
    const n = parseFloat(displayValue(value));
    if (!isNaN(n)) {
      if (n >= 80) return "ir-good";
      if (n >= 50) return "ir-ok";
      if (n >= 20) return "ir-warn";
      return "ir-bad";
    }
  }

  // Criticality
  if (col === "criticality" || col === "asset criticality") {
    if (val === "critical") return "lv-critical";
    if (val === "high") return "lv-high";
    if (val === "medium") return "lv-medium";
    if (val === "low") return "lv-low";
  }

  return "";
}

// ─── CSV builder ──────────────────────────────────────────────────────────────

function rowsToCsv(rows: ExportRow[], columns: string[], title: string) {
  const genDate = new Date().toLocaleString("mn-MN", {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
  const metaLine = `# ${title} — Үүсгэсэн: ${genDate} — ${rows.length} мөр`;
  const header = columns.map((col) => escapeCsvValue(columnLabel(col))).join(",");
  const body = rows.map((row) =>
    columns
      .map((col) => escapeCsvValue(formatCellValue(col, row[col])))
      .join(","),
  );
  return [`﻿${metaLine}`, header, ...body].join("\r\n");
}

// ─── Excel HTML builder ───────────────────────────────────────────────────────

const EXCEL_STYLES = `
  body { font-family: Calibri, Arial, sans-serif; font-size: 11pt; margin: 0; }
  table { border-collapse: collapse; }

  /* Title block */
  .rpt-title { font-size: 18pt; font-weight: bold; color: #1e3a5f; padding: 6px 0 2px; }
  .rpt-meta  { font-size: 10pt; color: #6b7280; padding: 0 0 4px; }

  /* Data table */
  .data-table { width: 100%; border-collapse: collapse; }

  /* Header row */
  .data-table thead th {
    background: #1e3a5f;
    color: #ffffff;
    font-weight: bold;
    font-size: 10pt;
    padding: 8px 10px;
    text-align: left;
    border: 1px solid #15294a;
    white-space: nowrap;
  }

  /* Data cells */
  .data-table tbody td {
    padding: 6px 10px;
    border: 1px solid #d1d5db;
    font-size: 10pt;
    vertical-align: top;
  }

  /* Zebra rows */
  .data-table tbody tr.even td { background: #f8fafc; }
  .data-table tbody tr.odd  td { background: #ffffff; }

  /* Risk level cells */
  .lv-critical { background: #fee2e2 !important; color: #991b1b; font-weight: bold; }
  .lv-high     { background: #ffedd5 !important; color: #9a3412; font-weight: bold; }
  .lv-medium   { background: #fef9c3 !important; color: #854d0e; font-weight: bold; }
  .lv-low      { background: #dcfce7 !important; color: #166534; font-weight: bold; }

  /* Score cells */
  .sc-critical { background: #fca5a5 !important; color: #7f1d1d; font-weight: bold; text-align: center; }
  .sc-high     { background: #fdba74 !important; color: #7c2d12; font-weight: bold; text-align: center; }
  .sc-medium   { background: #fde047 !important; color: #713f12; font-weight: bold; text-align: center; }
  .sc-low      { background: #86efac !important; color: #14532d; font-weight: bold; text-align: center; }

  /* Treatment cells */
  .tr-treat     { background: #dbeafe !important; color: #1e40af; font-weight: bold; }
  .tr-transfer  { background: #ede9fe !important; color: #5b21b6; font-weight: bold; }
  .tr-tolerate  { background: #d1fae5 !important; color: #065f46; font-weight: bold; }
  .tr-terminate { background: #ffe4e6 !important; color: #9f1239; font-weight: bold; }
  .tr-untreated { background: #fef3c7 !important; color: #92400e; font-weight: bold; }

  /* Implementation rate cells */
  .ir-good { background: #d1fae5 !important; color: #065f46; font-weight: bold; text-align: center; }
  .ir-ok   { background: #dbeafe !important; color: #1e40af; font-weight: bold; text-align: center; }
  .ir-warn { background: #fef9c3 !important; color: #854d0e; font-weight: bold; text-align: center; }
  .ir-bad  { background: #fee2e2 !important; color: #991b1b; font-weight: bold; text-align: center; }

  /* Totals / summary row */
  .data-table tfoot td {
    background: #1e3a5f !important;
    color: #ffffff;
    font-weight: bold;
    font-size: 10pt;
    padding: 7px 10px;
    border: 1px solid #15294a;
  }
`;

function rowsToExcelHtml(rows: ExportRow[], columns: string[], title: string) {
  const genDate = new Date().toLocaleString("mn-MN", {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

  // Column width declarations
  const colGroup = columns
    .map((col) => `<col style="width:${COLUMN_WIDTHS[col] ?? 120}px">`)
    .join("\n        ");

  // Header cells
  const thead = columns
    .map((col) => `<th>${escapeHtml(columnLabel(col))}</th>`)
    .join("");

  // Data rows
  const tbody = rows
    .map((row, idx) => {
      const rowClass = idx % 2 === 0 ? "even" : "odd";
      const cells = columns
        .map((col) => {
          const cls = getCellClass(col, row[col]);
          const val = escapeHtml(formatCellValue(col, row[col])) || "&nbsp;";
          return cls ? `<td class="${cls}">${val}</td>` : `<td>${val}</td>`;
        })
        .join("");
      return `<tr class="${rowClass}">${cells}</tr>`;
    })
    .join("\n        ");

  // Summary / totals row — count, and numeric column sums where relevant
  const NUMERIC_COLS = new Set([
    "Risk Count",
    "Open Vulnerabilities",
    "Mapped Risks",
    "Recommended Controls",
    "Implemented Controls",
  ]);
  const tfootCells = columns
    .map((col, i) => {
      if (i === 0) return `<td>Нийт: ${rows.length}</td>`;
      if (NUMERIC_COLS.has(col)) {
        const sum = rows.reduce((s, r) => s + Number(r[col] ?? 0), 0);
        return `<td style="text-align:center">${sum}</td>`;
      }
      return `<td></td>`;
    })
    .join("");

  return `<!doctype html>
<html xmlns:o="urn:schemas-microsoft-com:office:office"
      xmlns:x="urn:schemas-microsoft-com:office:excel"
      xmlns="http://www.w3.org/TR/REC-html40">
<head>
  <meta charset="utf-8" />
  <style>${EXCEL_STYLES}</style>
</head>
<body>
  <p class="rpt-title">${escapeHtml(title)}</p>
  <p class="rpt-meta">Үүсгэсэн: ${escapeHtml(genDate)} &nbsp;|&nbsp; ${rows.length} мөр</p>
  <br/>
  <table class="data-table">
    <colgroup>
        ${colGroup}
    </colgroup>
    <thead><tr>${thead}</tr></thead>
    <tbody>
        ${tbody}
    </tbody>
    <tfoot><tr>${tfootCells}</tr></tfoot>
  </table>
</body>
</html>`;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function exportRows({
  rows,
  columns,
  title,
  requestedFormat,
}: {
  rows: ExportRow[];
  columns: string[];
  title: string;
  requestedFormat: string | null;
}) {
  const format = normalizeFormat(requestedFormat);
  const body =
    format === "xls"
      ? rowsToExcelHtml(rows, columns, title)
      : rowsToCsv(rows, columns, title);
  const datePart = new Date().toISOString().slice(0, 10);
  const filename = `${safeFilePart(title)}-${datePart}.${format}`;

  return new NextResponse(body, {
    headers: {
      "Content-Type": MIME_TYPES[format],
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Cache-Control": "no-store",
    },
  });
}
