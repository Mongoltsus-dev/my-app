import { pool } from "@/lib/db";
import { NextRequest, NextResponse } from "next/server";

type GapPayload = {
  subcategory_code?: unknown;
  target_tier?: unknown;
  priority?: unknown;
  owner?: unknown;
  due_date?: unknown;
};

type AssetPostureRow = {
  id: number;
  criticality: string | null;
  data_classification: string | null;
  internet_exposed: boolean | null;
  backup_enabled: boolean | null;
  encryption_enabled: boolean | null;
  mfa_enabled: boolean | null;
  logging_enabled: boolean | null;
};

type VulnerabilitySummary = {
  open_count: string;
  critical_high_count: string;
};

type SavedGapRow = {
  subcategory_code: string;
  target_tier: number;
  owner: string | null;
};

type AssetScope = {
  total_assets: number;
  critical_assets: number;
  sensitive_assets: number;
  internet_exposed_assets: number;
  open_vulnerabilities: number;
  critical_high_vulnerabilities: number;
  mfa_coverage: number;
  encryption_coverage: number;
  logging_coverage: number;
  backup_coverage: number;
};

type AssetDrivenGap = {
  subcategory_code: string;
  subcategory_name: string;
  nist_function: string;
  current_tier: number;
  target_tier: number;
  priority: "Critical" | "High" | "Medium" | "Low";
  rationale: string;
  owner: string;
};

async function ensureCsfProfileSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS assets (
      id SERIAL PRIMARY KEY,
      asset_name VARCHAR(255) NOT NULL DEFAULT 'Unnamed Asset',
      criticality VARCHAR(100) NOT NULL DEFAULT 'Medium',
      data_classification VARCHAR(50),
      access_level VARCHAR(50),
      internet_exposed BOOLEAN DEFAULT FALSE,
      backup_enabled BOOLEAN DEFAULT FALSE,
      encryption_enabled BOOLEAN DEFAULT FALSE,
      mfa_enabled BOOLEAN DEFAULT FALSE,
      logging_enabled BOOLEAN DEFAULT FALSE,
      status VARCHAR(50) DEFAULT 'Active',
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);
  const assetColumns: [string, string][] = [
    ["criticality", "VARCHAR(100) NOT NULL DEFAULT 'Medium'"],
    ["data_classification", "VARCHAR(50)"],
    ["access_level", "VARCHAR(50)"],
    ["internet_exposed", "BOOLEAN DEFAULT FALSE"],
    ["backup_enabled", "BOOLEAN DEFAULT FALSE"],
    ["encryption_enabled", "BOOLEAN DEFAULT FALSE"],
    ["mfa_enabled", "BOOLEAN DEFAULT FALSE"],
    ["logging_enabled", "BOOLEAN DEFAULT FALSE"],
    ["status", "VARCHAR(50) DEFAULT 'Active'"],
  ];
  for (const [column, definition] of assetColumns) {
    await pool.query(
      `ALTER TABLE assets ADD COLUMN IF NOT EXISTS ${column} ${definition}`,
    );
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id SERIAL PRIMARY KEY,
      asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
      title VARCHAR(255) NOT NULL DEFAULT 'Untitled vulnerability',
      severity VARCHAR(50) NOT NULL DEFAULT 'Medium',
      status VARCHAR(50) DEFAULT 'open',
      source VARCHAR(100) DEFAULT 'manual',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  const vulnerabilityColumns: [string, string][] = [
    ["asset_id", "INTEGER REFERENCES assets(id) ON DELETE CASCADE"],
    ["title", "VARCHAR(255) NOT NULL DEFAULT 'Untitled vulnerability'"],
    ["severity", "VARCHAR(50) NOT NULL DEFAULT 'Medium'"],
    ["status", "VARCHAR(50) DEFAULT 'open'"],
    ["source", "VARCHAR(100) DEFAULT 'manual'"],
  ];
  for (const [column, definition] of vulnerabilityColumns) {
    await pool.query(
      `ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS ${column} ${definition}`,
    );
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS csf_profile_gaps (
      id SERIAL PRIMARY KEY,
      subcategory_code VARCHAR(50) UNIQUE NOT NULL,
      subcategory_name TEXT NOT NULL,
      nist_function VARCHAR(50),
      current_tier INTEGER NOT NULL DEFAULT 1 CHECK (current_tier BETWEEN 1 AND 4),
      target_tier INTEGER NOT NULL DEFAULT 3 CHECK (target_tier BETWEEN 1 AND 4),
      priority VARCHAR(20) DEFAULT 'Medium',
      rationale TEXT,
      owner VARCHAR(255),
      due_date DATE,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`CREATE SEQUENCE IF NOT EXISTS csf_profile_gaps_id_seq`);
  await pool.query(
    `ALTER TABLE csf_profile_gaps DROP CONSTRAINT IF EXISTS singleton_assessment_scope`,
  );
  await pool.query(
    `SELECT setval('csf_profile_gaps_id_seq', GREATEST((SELECT COALESCE(MAX(id), 0) FROM csf_profile_gaps), 1))`,
  );
  await pool.query(
    `ALTER TABLE csf_profile_gaps ALTER COLUMN id SET DEFAULT nextval('csf_profile_gaps_id_seq')`,
  );
  await pool.query(
    `ALTER TABLE csf_profile_gaps ADD COLUMN IF NOT EXISTS subcategory_code VARCHAR(50)`,
  );
  await pool.query(
    `ALTER TABLE csf_profile_gaps ADD COLUMN IF NOT EXISTS subcategory_name TEXT`,
  );
  await pool.query(
    `ALTER TABLE csf_profile_gaps ADD COLUMN IF NOT EXISTS nist_function VARCHAR(50)`,
  );
  await pool.query(
    `ALTER TABLE csf_profile_gaps ADD COLUMN IF NOT EXISTS current_tier INTEGER DEFAULT 1`,
  );
  await pool.query(
    `ALTER TABLE csf_profile_gaps ADD COLUMN IF NOT EXISTS target_tier INTEGER DEFAULT 3`,
  );
  await pool.query(
    `ALTER TABLE csf_profile_gaps ADD COLUMN IF NOT EXISTS priority VARCHAR(20) DEFAULT 'Medium'`,
  );
  await pool.query(
    `ALTER TABLE csf_profile_gaps ADD COLUMN IF NOT EXISTS rationale TEXT`,
  );
  await pool.query(
    `ALTER TABLE csf_profile_gaps ADD COLUMN IF NOT EXISTS owner VARCHAR(255)`,
  );
  await pool.query(
    `ALTER TABLE csf_profile_gaps ADD COLUMN IF NOT EXISTS due_date DATE`,
  );
  await pool.query(
    `ALTER TABLE csf_profile_gaps ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()`,
  );
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'csf_profile_gaps_subcategory_code_key'
      ) THEN
        ALTER TABLE csf_profile_gaps
        ADD CONSTRAINT csf_profile_gaps_subcategory_code_key UNIQUE (subcategory_code);
      END IF;
    END $$;
  `);
}

// ── Policy compliance factor ───────────────────────────────────────────────
// Returns: approved & current required policies / total required policies
async function getPolicyCompliance(): Promise<{
  totalRequired: number;
  approvedCount: number;
  pendingCount: number;
  draftCount: number;
  compliancePct: number;
  tierCap: number; // 1-4: cap applied to Govern tier scores
}> {
  const empty = { totalRequired: 0, approvedCount: 0, pendingCount: 0, draftCount: 0, compliancePct: 0, tierCap: 1 };
  try {
    const tableCheck = await pool.query("SELECT to_regclass('policies') AS name");
    if (!tableCheck.rows[0]?.name) return empty;

    const result = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE is_required = TRUE)::int                                   AS total_required,
        COUNT(*) FILTER (
          WHERE is_required = TRUE AND status = 'Approved'
            AND (next_review_at IS NULL OR next_review_at > NOW())
        )::int                                                                             AS approved_count,
        COUNT(*) FILTER (WHERE is_required = TRUE AND status = 'Pending Approval')::int   AS pending_count,
        COUNT(*) FILTER (WHERE is_required = TRUE AND status = 'Draft')::int              AS draft_count
      FROM policies
    `);

    const row = result.rows[0];
    const total   = row?.total_required  ?? 0;
    const approved= row?.approved_count  ?? 0;
    const pending = row?.pending_count   ?? 0;
    const draft   = row?.draft_count     ?? 0;

    if (total === 0) return empty;

    const pct = Math.round((approved / total) * 100);
    // Tier cap for Govern function: no policies → tier 1, all approved → tier 4
    const tierCap = pct >= 80 ? 4 : pct >= 50 ? 3 : pct >= 20 ? 2 : 1;

    return { totalRequired: total, approvedCount: approved, pendingCount: pending, draftCount: draft, compliancePct: pct, tierCap };
  } catch {
    // If policies table not ready, don't penalize
    return { totalRequired: 0, approvedCount: 0, pendingCount: 0, draftCount: 0, compliancePct: 0, tierCap: 4 };
  }
}

export async function GET() {
  try {
    await ensureCsfProfileSchema();
    const [assetScope, policyCompliance] = await Promise.all([
      getAssetScope(),
      getPolicyCompliance(),
    ]);
    const gaps = await syncAssetDrivenGaps(assetScope, policyCompliance.tierCap);

    return NextResponse.json({
      success: true,
      assetScope,
      gaps,
      policyCompliance,
    });
  } catch (error) {
    console.error("CSF profile fetch error:", error);
    const message =
      error instanceof Error ? error.message : "Failed to fetch CSF profile";
    return NextResponse.json({ message }, { status: 500 });
  }
}

export async function PUT(req: NextRequest) {
  try {
    await ensureCsfProfileSchema();
    const body = await req.json();
    const gaps = Array.isArray(body?.gaps) ? (body.gaps as GapPayload[]) : [];

    for (const gap of gaps) {
      const code = toStringValue(gap.subcategory_code);
      if (!code) continue;

      await pool.query(
        `UPDATE csf_profile_gaps
            SET target_tier = COALESCE($1, target_tier),
                priority = COALESCE($2, priority),
                owner = COALESCE($3, owner),
                due_date = COALESCE($4, due_date),
                updated_at = NOW()
          WHERE subcategory_code = $5`,
        [
          gap.target_tier === undefined ? null : clampTier(gap.target_tier, 3),
          toStringValue(gap.priority),
          toStringValue(gap.owner),
          toDateOrNull(gap.due_date),
          code,
        ],
      );
    }

    return GET();
  } catch (error) {
    console.error("CSF profile save error:", error);
    const message =
      error instanceof Error ? error.message : "Failed to save CSF profile";
    return NextResponse.json({ message }, { status: 500 });
  }
}

async function getAssetScope(): Promise<AssetScope> {
  const [assetsResult, vulnerabilityResult] = await Promise.all([
    pool.query<AssetPostureRow>(
      `SELECT id, criticality, data_classification,
              internet_exposed OR access_level IN ('Public web access', 'Public API exposed') AS internet_exposed,
              backup_enabled, encryption_enabled, mfa_enabled, logging_enabled
         FROM assets
        WHERE COALESCE(status, 'Active') <> 'Retired'`,
    ),
    pool.query<VulnerabilitySummary>(
      `SELECT COUNT(*) FILTER (
                WHERE LOWER(COALESCE(v.status, 'open')) IN ('open', 'in_progress')
              ) AS open_count,
              COUNT(*) FILTER (
                WHERE LOWER(COALESCE(v.status, 'open')) IN ('open', 'in_progress')
                  AND LOWER(COALESCE(v.severity, '')) IN ('critical', 'high')
              ) AS critical_high_count
         FROM vulnerabilities v
         JOIN assets a ON a.id = v.asset_id
        WHERE COALESCE(a.status, 'Active') <> 'Retired'
          AND NOT (COALESCE(v.source, '') = 'cisa_kev' AND v.asset_id IS NULL)`,
    ),
  ]);

  const assets = assetsResult.rows;
  const vulnerabilitySummary = vulnerabilityResult.rows[0] ?? {
    open_count: "0",
    critical_high_count: "0",
  };

  return {
    total_assets: assets.length,
    critical_assets: assets.filter((asset) =>
      isHighCriticality(asset.criticality),
    ).length,
    sensitive_assets: assets.filter((asset) =>
      isSensitiveData(asset.data_classification),
    ).length,
    internet_exposed_assets: assets.filter((asset) => asset.internet_exposed === true)
      .length,
    open_vulnerabilities: Number(vulnerabilitySummary.open_count ?? 0),
    critical_high_vulnerabilities: Number(
      vulnerabilitySummary.critical_high_count ?? 0,
    ),
    mfa_coverage: coverage(assets, (asset) => asset.mfa_enabled),
    encryption_coverage: coverage(assets, (asset) => asset.encryption_enabled),
    logging_coverage: coverage(assets, (asset) => asset.logging_enabled),
    backup_coverage: coverage(assets, (asset) => asset.backup_enabled),
  };
}

async function syncAssetDrivenGaps(assetScope: AssetScope, policyTierCap = 4) {
  const savedResult = await pool.query<SavedGapRow>(
    `SELECT subcategory_code, target_tier, owner
       FROM csf_profile_gaps
      WHERE subcategory_code IS NOT NULL`,
  );
  const saved = new Map(
    savedResult.rows.map((row) => [row.subcategory_code, row]),
  );
  const sensitiveOrCritical =
    assetScope.sensitive_assets > 0 || assetScope.critical_assets > 0;

  // Govern tier is capped by policy compliance:
  // no approved policies → max tier 1, all approved → full tier based on asset posture
  const govCap = policyTierCap;

  const definitions: AssetDrivenGap[] = [
    // ── Govern ────────────────────────────────────────────────────────────────
    buildGap({
      code: "GV.RM-01",
      name: "Эрсдэлийн менежментийн зорилтуудыг байгууллагын оролцогч талуудтай тохиролцон тогтоосон",
      nistFunction: "Govern",
      currentTier: Math.min(assetScope.total_assets > 0 ? 2 : 1, govCap),
      defaultTargetTier: sensitiveOrCritical ? 4 : 3,
      fallbackOwner: "CISO / Эрсдэлийн хариуцагч",
      rationale: `${assetScope.total_assets} хөрөнгө бүртгэгдсэн. Албан ёсны эрсдэлийн менежментийн зорилт болон оролцогч талуудын тохиролцоо нь эрсдэлийн бүх шийдвэрийг дэмжинэ.`,
      saved: saved.get("GV.RM-01"),
    }),
    buildGap({
      code: "GV.PO-01",
      name: "Кибер аюулгүй байдлын эрсдэлийг удирдах бодлого тогтоогдсон, мэдэгдсэн, хэрэгжүүлэгдсэн",
      nistFunction: "Govern",
      currentTier: Math.min(sensitiveOrCritical ? 2 : 1, govCap),
      defaultTargetTier: sensitiveOrCritical ? 4 : 3,
      fallbackOwner: "МТ удирдлага",
      rationale: `Байгууллага ${assetScope.sensitive_assets} мэдрэмтгий, ${assetScope.critical_assets} чухал хөрөнгөтэй. Эдгээр хөрөнгийн хяналтыг удирдахад албан ёсны кибер аюулгүй байдлын бодлого шаардлагатай.`,
      saved: saved.get("GV.PO-01"),
    }),
    buildGap({
      code: "GV.RR-01",
      name: "Байгууллагын удирдлага кибер аюулгүй байдлын эрсдэлд хариуцлагатай",
      nistFunction: "Govern",
      currentTier: Math.min(1, govCap),
      defaultTargetTier: 3,
      fallbackOwner: "Гүйцэтгэх удирдлага / Захирал зөвлөл",
      rationale: "Удирдлагын кибер аюулгүй байдлын эрсдэлд хариуцлага хүлээх нь NIST CSF 2.0-ийн үндсэн засаглалын шаардлага юм.",
      saved: saved.get("GV.RR-01"),
    }),
    // ── Protect ──────────────────────────────────────────────────────────────
    buildGap({
      code: "PR.AA-01",
      name: "Зөвшөөрөлтэй хэрэглэгч, үйлчилгээ, техник хангамжийн хандалтын удирдлага",
      nistFunction: "Protect",
      currentTier: tierFromCoverage(assetScope.mfa_coverage),
      defaultTargetTier: sensitiveOrCritical ? 4 : 3,
      fallbackOwner: "Аюулгүй байдлын баг",
      rationale: `Идэвхтэй хөрөнгийн ${assetScope.mfa_coverage}% олон хүчин зүйлийн нотолгоог идэвхжүүлсэн. Интернэтэд нээлттэй болон мэдрэмтгий хөрөнгүүд таних хяналтын зорилтот түвшинг өндөрсгөнө.`,
      saved: saved.get("PR.AA-01"),
    }),
    buildGap({
      code: "PR.DS-01",
      name: "Хадгалагдаж байгаа өгөгдлийн хамгаалалт хангагдсан",
      nistFunction: "Protect",
      currentTier: tierFromCoverage(assetScope.encryption_coverage),
      defaultTargetTier: sensitiveOrCritical ? 4 : 3,
      fallbackOwner: "Өгөгдлийн хамгааллын хариуцагч",
      rationale: `Идэвхтэй хөрөнгийн ${assetScope.encryption_coverage}% шифрлэлтийг идэвхжүүлсэн. ${assetScope.sensitive_assets} мэдрэмтгий өгөгдлийн хөрөнгө байна.`,
      saved: saved.get("PR.DS-01"),
    }),
    // ── Detect ───────────────────────────────────────────────────────────────
    buildGap({
      code: "DE.CM-01",
      name: "Сүлжээ болон сүлжээний үйлчилгээг хортой үйл явдал илрүүлэх зорилгоор хянана",
      nistFunction: "Detect",
      currentTier: tierFromCoverage(assetScope.logging_coverage),
      defaultTargetTier: assetScope.internet_exposed_assets > 0 ? 4 : 3,
      fallbackOwner: "МТ-ийн үйл ажиллагааны алба",
      rationale: `Бүртгэлтэй хөрөнгийн ${assetScope.logging_coverage}% лог бүртгэлийн хамрах хүрээтэй.`,
      saved: saved.get("DE.CM-01"),
    }),
    // ── Identify ─────────────────────────────────────────────────────────────
    buildGap({
      code: "ID.RA-01",
      name: "Хөрөнгийн эмзэг байдлыг тодорхойлж баримтжуулсан",
      nistFunction: "Identify",
      currentTier: assetScope.open_vulnerabilities > 0 ? 2 : 1,
      defaultTargetTier: assetScope.critical_high_vulnerabilities > 0 ? 4 : 3,
      fallbackOwner: "Эрсдэлийн менежментийн хариуцагч",
      rationale: `${assetScope.open_vulnerabilities} нээлттэй эмзэг байдлын олдвор байгаа бөгөөд ${assetScope.critical_high_vulnerabilities} нь ноцтой эсвэл өндөр зэрэглэлтэй.`,
      saved: saved.get("ID.RA-01"),
    }),
    // ── Respond ──────────────────────────────────────────────────────────────
    buildGap({
      code: "RS.MA-01",
      name: "Аюулгүй байдлын зөрчлийн хариу арга хэмжээний төлөвлөгөөг холбогдох талуудтай хамтран хэрэгжүүлнэ",
      nistFunction: "Respond",
      currentTier: assetScope.critical_high_vulnerabilities > 0 ? 2 : 3,
      defaultTargetTier: assetScope.critical_high_vulnerabilities > 0 ? 4 : 3,
      fallbackOwner: "Зөрчлийн хариу арга хэмжээний ахлах",
      rationale: `${assetScope.critical_high_vulnerabilities} өндөр болон ноцтой зэрэглэлтэй нээлттэй эмзэг байдлын олдвор нь зохицуулалттай хариу арга хэмжээний хэрэгцээг нэмэгдүүлдэг.`,
      saved: saved.get("RS.MA-01"),
    }),
    // ── Recover ──────────────────────────────────────────────────────────────
    buildGap({
      code: "RC.RP-01",
      name: "Кибер аюулгүй байдлын зөрчлийн үед болон дараа нь сэргээх төлөвлөгөөг хэрэгжүүлнэ",
      nistFunction: "Recover",
      currentTier: tierFromCoverage(assetScope.backup_coverage),
      defaultTargetTier: sensitiveOrCritical ? 4 : 3,
      fallbackOwner: "Дэд бүтцийн баг",
      rationale: `Идэвхтэй хөрөнгийн ${assetScope.backup_coverage}% нөөцлөлтийг идэвхжүүлсэн. Чухал болон мэдрэмтгий хөрөнгүүд хамрагдах үед сэргээлтийн зорилт өндөрсөнө.`,
      saved: saved.get("RC.RP-01"),
    }),
  ];

  for (const gap of definitions) {
    await pool.query(
      `INSERT INTO csf_profile_gaps
         (subcategory_code, subcategory_name, nist_function, current_tier,
          target_tier, priority, rationale, owner, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
       ON CONFLICT (subcategory_code)
       DO UPDATE SET
         nist_function = EXCLUDED.nist_function,
         current_tier = EXCLUDED.current_tier,
         target_tier = EXCLUDED.target_tier,
         priority = EXCLUDED.priority,
         rationale = EXCLUDED.rationale,
         owner = EXCLUDED.owner,
         updated_at = NOW()`,
      [
        gap.subcategory_code,
        gap.subcategory_name,
        gap.nist_function,
        gap.current_tier,
        gap.target_tier,
        gap.priority,
        gap.rationale,
        gap.owner,
      ],
    );
  }

  const result = await pool.query(
    `SELECT id, subcategory_code, subcategory_name, nist_function,
            current_tier, target_tier,
            current_tier - target_tier AS gap,
            priority, rationale, owner, due_date, updated_at
       FROM csf_profile_gaps
      WHERE subcategory_code IS NOT NULL
      ORDER BY
        CASE priority
          WHEN 'Critical' THEN 1
          WHEN 'High' THEN 2
          WHEN 'Medium' THEN 3
          WHEN 'Low' THEN 4
          ELSE 5
        END,
        subcategory_code`,
  );

  return result.rows;
}

function buildGap(input: {
  code: string;
  name: string;
  nistFunction: string;
  currentTier: number;
  defaultTargetTier: number;
  fallbackOwner: string;
  rationale: string;
  saved?: SavedGapRow;
}): AssetDrivenGap {
  const targetTier = input.saved?.target_tier ?? input.defaultTargetTier;
  const gap = input.currentTier - targetTier;
  return {
    subcategory_code: input.code,
    subcategory_name: input.name,
    nist_function: input.nistFunction,
    current_tier: input.currentTier,
    target_tier: targetTier,
    priority: priorityFromGap(gap, targetTier),
    rationale: input.rationale,
    owner: input.saved?.owner ?? input.fallbackOwner,
  };
}

function coverage<T>(items: T[], predicate: (item: T) => boolean | null) {
  if (items.length === 0) return 0;
  const covered = items.filter((item) => Boolean(predicate(item))).length;
  return Math.round((covered / items.length) * 100);
}

function tierFromCoverage(percent: number) {
  if (percent >= 90) return 4;
  if (percent >= 70) return 3;
  if (percent >= 40) return 2;
  return 1;
}

function priorityFromGap(gap: number, targetTier: number) {
  if (gap <= -2 && targetTier >= 4) return "Critical";
  if (gap <= -2) return "High";
  if (gap < 0) return "Medium";
  return "Low";
}

function toStringValue(value: unknown) {
  if (value === undefined || value === null) return null;
  const trimmed = String(value).trim();
  return trimmed.length > 0 ? trimmed : null;
}

function clampTier(value: unknown, fallback: number) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(4, Math.max(1, Math.trunc(parsed)));
}

function toDateOrNull(value: unknown) {
  const raw = toStringValue(value);
  if (!raw) return null;
  return /^\d{4}-\d{2}-\d{2}$/.test(raw) ? raw : null;
}

function normalize(value: string | null) {
  return (value ?? "").toLowerCase().trim();
}

function isHighCriticality(value: string | null) {
  return /critical|tier 0|tier 1|high|mission/.test(normalize(value));
}

function isSensitiveData(value: string | null) {
  return /phi|pii|pci|confidential|restricted|sensitive|financial|hipaa|high/.test(
    normalize(value),
  );
}
