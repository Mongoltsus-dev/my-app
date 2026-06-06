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
import { Upload } from "lucide-react";
import { memo, useState } from "react";

interface ImportAssetsModalProps {
  onImported: () => void;
}

type ImportResult = {
  success: boolean;
  insertedCount: number;
  failedCount: number;
  message?: string;
  failed?: Array<{ rowIndex: number; asset_name?: string; error: string }>;
};

const HEADER_ALIASES: Record<string, string> = {
  asset_id: "asset_code",
  asset_code: "asset_code",
  хөрөнгийн_код: "asset_code",
  asset_name: "asset_name",
  хөрөнгийн_нэр: "asset_name",
  asset_type: "asset_type",
  хөрөнгийн_төрөл: "asset_type",
  asset_type_id: "asset_type_id",
  business_owner: "business_owner",
  бизнесийн_хариуцагч: "business_owner",
  technical_owner: "technical_owner",
  техникийн_хариуцагч: "technical_owner",
  criticality: "criticality",
  чухал_байдлын_түвшин: "criticality",
  data_classification: "data_classification",
  өгөгдлийн_ангилал: "data_classification",
  stored_data_classification: "data_classification",
  access_level: "access_level",
  хандалтын_түвшин: "access_level",
  exposure_level: "access_level",
  authentication_method: "authentication_method",
  танин_баталгаажуулалт: "authentication_method",
  authentication_type: "authentication_method",
  supports_critical_service: "supports_critical_service",
  чухал_үйлчилгээ_дэмждэг: "supports_critical_service",
  critical_service: "supports_critical_service",
  hosting: "hosting",
  байршуулалт: "hosting",
  rto_hours: "rto_hours",
  rto_цаг: "rto_hours",
  rpo_hours: "rpo_hours",
  rpo_цаг: "rpo_hours",
  department: "department",
  хэлтэс: "department",
  status: "status",
  төлөв: "status",
  internet_exposed: "internet_exposed",
  интернетэд_нээлттэй: "internet_exposed",
  backup_enabled: "backup_enabled",
  нөөцлөлт_идэвхтэй: "backup_enabled",
  encryption_enabled: "encryption_enabled",
  шифрлэлт_идэвхтэй: "encryption_enabled",
  mfa_enabled: "mfa_enabled",
  mfa_идэвхтэй: "mfa_enabled",
  logging_enabled: "logging_enabled",
  лог_идэвхтэй: "logging_enabled",
  // Second Excel columns
  primary_region: "region",
  region: "region",
  бүс_нутаг: "region",
  key_users_customers: "key_users_customers",
  key_users: "key_users_customers",
  гол_хэрэглэгчид: "key_users_customers",
  customers: "key_users_customers",
  // Legacy column names map to their new boolean equivalents (TRUE if non-empty).
  // The conversion is handled in transformRow below.
  logging_to_siem: "logging_enabled",
  siem: "logging_enabled",
  edr_endpoint_security: "edr_enabled",
  edr: "edr_enabled",
  endpoint_security: "edr_enabled",
  edr_enabled: "edr_enabled",
  edr_идэвхтэй: "edr_enabled",
  vuln_scanning: "vuln_scanning_enabled",
  vulnerability_scanning: "vuln_scanning_enabled",
  vuln_scanning_enabled: "vuln_scanning_enabled",
  эмзэг_байдлын_скан_идэвхтэй: "vuln_scanning_enabled",
  backup_method: "backup_enabled",
  cmdb_ci_id: "cmdb_ci_id",
  notes: "notes",
  тэмдэглэл: "notes",
};

const REQUIRED_FIELDS = ["asset_name", "criticality"];

const EXAMPLE_HEADERS =
  "Хөрөнгийн_код,Хөрөнгийн_нэр,Хөрөнгийн_төрөл,Бизнесийн_хариуцагч,Техникийн_хариуцагч,Чухал_байдлын_түвшин,Өгөгдлийн_ангилал,Байршуулалт,Бүс_нутаг,Гол_хэрэглэгчид,RTO_цаг,RPO_цаг,Нөөцлөлт_идэвхтэй,Шифрлэлт_идэвхтэй,MFA_идэвхтэй,Лог_идэвхтэй,EDR_идэвхтэй,Эмзэг_байдлын_скан_идэвхтэй,Тэмдэглэл";

const normalizeHeader = (header: string) =>
  header
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9\u0400-\u04ff]+/g, "_")
    .replace(/^_+|_+$/g, "");

const splitRows = (text: string) => {
  const rows: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const next = text[i + 1];

    if (ch === '"') {
      if (inQuotes && next === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if (!inQuotes && (ch === "\n" || ch === "\r")) {
      if (ch === "\r" && next === "\n") i++;
      if (current.trim().length > 0) {
        rows.push(current);
      }
      current = "";
      continue;
    }

    current += ch;
  }

  if (current.trim().length > 0) {
    rows.push(current);
  }

  return rows;
};

const splitColumns = (row: string, delimiter: string) => {
  const columns: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < row.length; i++) {
    const ch = row[i];
    const next = row[i + 1];

    if (ch === '"') {
      if (inQuotes && next === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if (!inQuotes && ch === delimiter) {
      columns.push(current.trim());
      current = "";
      continue;
    }

    current += ch;
  }

  columns.push(current.trim());
  return columns;
};

const parseAssetRows = (rawText: string) => {
  const rows = splitRows(rawText);
  if (rows.length < 2) {
    throw new Error(
      "CSV/TSV файл нь толгой мөр болон дор хаяж нэг өгөгдлийн мөртэй байх ёстой.",
    );
  }

  const headerRow = rows[0];
  const delimiter =
    headerRow.includes("\t") && !headerRow.includes(",") ? "\t" : ",";
  const rawHeaders = splitColumns(headerRow, delimiter);

  const mappedHeaders = rawHeaders.map((header) => {
    const normalized = normalizeHeader(header);
    return HEADER_ALIASES[normalized] || normalized;
  });

  const hasRequiredHeaders =
    REQUIRED_FIELDS.every((field) => mappedHeaders.includes(field)) &&
    (mappedHeaders.includes("asset_type") ||
      mappedHeaders.includes("asset_type_id"));

  if (!hasRequiredHeaders) {
    throw new Error(
      "Заавал байх багана дутуу байна. Хөрөнгийн нэр, чухал байдлын түвшин, хөрөнгийн төрөл эсвэл хөрөнгийн төрлийн ID багануудыг оруулна уу.",
    );
  }

  const parsedRows: Array<Record<string, string>> = [];

  for (let i = 1; i < rows.length; i++) {
    const values = splitColumns(rows[i], delimiter);
    const row: Record<string, string> = {};

    mappedHeaders.forEach((key, index) => {
      const incoming = values[index] ?? "";
      // Legacy freetext columns (logging_to_siem / edr_endpoint_security /
      // vuln_scanning / backup_method) are aliased to their new boolean field
      // names. If user's CSV has a tool name like "Splunk" or "CrowdStrike",
      // collapse it to "true" so the API's toBoolean() helper picks it up.
      // For empty values we leave them empty (= false on the backend).
      const isBoolField =
        key === "logging_enabled" ||
        key === "edr_enabled" ||
        key === "vuln_scanning_enabled" ||
        key === "backup_enabled";
      if (isBoolField && incoming.trim().length > 0) {
        const lower = incoming.trim().toLowerCase();
        const explicitBool = [
          "true",
          "false",
          "yes",
          "no",
          "y",
          "n",
          "1",
          "0",
          "enabled",
          "disabled",
          "on",
          "off",
        ];
        // If the cell is something like "Splunk" or "CrowdStrike" (i.e. NOT an
        // explicit boolean), treat the mere presence as truthy. Otherwise
        // pass through so toBoolean handles "no" / "false" correctly.
        row[key] = explicitBool.includes(lower) ? lower : "true";
      } else {
        row[key] = incoming;
      }
    });

    const hasAnyValue = Object.values(row).some(
      (value) => value.trim().length > 0,
    );
    if (!hasAnyValue) continue;

    parsedRows.push(row);
  }

  if (parsedRows.length === 0) {
    throw new Error("Сонгосон файлд хүчинтэй өгөгдлийн мөр олдсонгүй.");
  }

  return parsedRows;
};

function ImportAssetsModal({ onImported }: ImportAssetsModalProps) {
  const [open, setOpen] = useState(false);
  const [rawText, setRawText] = useState("");
  const [fileName, setFileName] = useState("");
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<ImportResult | null>(null);

  const handleFilePick = async (file?: File | null) => {
    if (!file) return;
    const content = await file.text();
    setFileName(file.name);
    setRawText(content);
    setError("");
    setResult(null);
  };

  const handleImport = async () => {
    try {
      setImporting(true);
      setError("");
      setResult(null);

      const assets = parseAssetRows(rawText);

      const response = await fetch("/api/assets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ assets }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(
          data?.error || data?.message || "Импорт амжилтгүй боллоо.",
        );
      }

      setResult(data);
      if ((data?.insertedCount || 0) > 0) {
        onImported();
      }
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Хөрөнгө импортолж чадсангүй.",
      );
    } finally {
      setImporting(false);
    }
  };

  const resetDialog = (nextOpen: boolean) => {
    setOpen(nextOpen);
    if (!nextOpen) {
      setError("");
      setResult(null);
    }
  };

  return (
    <Dialog open={open} onOpenChange={resetDialog}>
      <DialogTrigger asChild>
        <Button variant="outline" className="gap-2">
          <Upload className="h-4 w-4" />
          CSV импортлох
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-3xl bg-white border-gray-200 text-slate-900">
        <DialogHeader>
          <DialogTitle>Хөрөнгө импортлох</DialogTitle>
          <DialogDescription className="sr-only">
            CSV эсвэл TSV файлаас хөрөнгийн бүртгэл импортлох цонх.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-2">
            <Input
              id="assetCsvFile"
              type="file"
              accept=".csv,.tsv,text/csv,text/tab-separated-values"
              onChange={(e) => handleFilePick(e.target.files?.[0])}
            />
            {fileName && (
              <p className="text-xs text-slate-600">
                Сонгосон файл: {fileName}
              </p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="assetCsvText">Гараар оруулах</Label>
            <textarea
              id="assetCsvText"
              value={rawText}
              onChange={(e) => {
                setRawText(e.target.value);
                setError("");
                setResult(null);
              }}
              rows={9}
              placeholder={EXAMPLE_HEADERS}
              className="w-full px-3 py-2 rounded-md border border-slate-300 bg-white text-slate-900 resize-y"
            />
            <p className="text-xs text-slate-600">
              Заавал байх баганууд: Нэр, чухал байдлын түвшин, хөрөнгийн төрөл
            </p>
          </div>

          {error && (
            <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
              {error}
            </div>
          )}

          {result && (
            <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-800 space-y-1">
              <p>{result.message || "Импорт дууслаа."}</p>
              <p>
                Нэмэгдсэн: {result.insertedCount} | Амжилтгүй:{" "}
                {result.failedCount}
              </p>
              {result.failed && result.failed.length > 0 && (
                <div className="pt-1 text-xs text-slate-700 space-y-1">
                  {result.failed.slice(0, 5).map((item) => (
                    <p key={`${item.rowIndex}-${item.asset_name || "unknown"}`}>
                      Мөр {item.rowIndex}
                      {item.asset_name ? ` (${item.asset_name})` : ""}:{" "}
                      {item.error}
                    </p>
                  ))}
                </div>
              )}
            </div>
          )}

          <div className="flex justify-end gap-2 pt-2 border-t border-slate-200">
            <Button variant="outline" onClick={() => setOpen(false)}>
              Болих
            </Button>
            <Button
              onClick={handleImport}
              disabled={importing || !rawText.trim()}
              className="bg-blue-600 hover:bg-blue-700 text-white"
            >
              {importing ? "Импортолж байна..." : "Хөрөнгө импортлох"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default memo(ImportAssetsModal);
