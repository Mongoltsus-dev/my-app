import { pool } from "@/lib/db";
import { ensureBusinessProcessSchema } from "@/lib/business-processes-schema";
import { ROLE_MANAGER, getCurrentUser } from "@/lib/current-user";
import {
  FUNCTION_BY_CODE,
  MANDATORY_SUBCATEGORY_IDS,
  normalizeScopeStatus,
  type CsfFunctionCode,
  type CsfScopeCatalogItem,
  type CsfScopeStatus,
} from "@/lib/nist-csf-scope";
import { NextRequest, NextResponse } from "next/server";

type SavedScopeRow = {
  subcategory_id: string;
  scope_status: string | null;
  exclusion_reason: string | null;
  updated_at: string | null;
};

type ScopeUpdate = {
  subcategory_id?: unknown;
  scope_status?: unknown;
  exclusion_reason?: unknown;
};

type FunctionScopeSummary = {
  function_code: string;
  nist_function: string;
  function_name_mn: string;
  total: number;
  mandatory: number;
  in_scope: number;
  out_of_scope: number;
  undecided: number;
};

type AssessmentScopeSettings = {
  id: number;
  assessment_name: string;
  assessment_type: string;
  selected_department_ids: number[];
  selected_business_process_ids: number[];
  selected_asset_ids: number[];
  status: string;
  updated_at: string | null;
};

type ScopeInventoryAsset = {
  id: number;
  asset_name: string;
  asset_code: string | null;
  asset_type: string | null;
  department: string | null;
  criticality: string | null;
  internet_exposed: boolean;
  status: string | null;
  business_owner: string | null;
  technical_owner: string | null;
  business_process_ids: number[];
};

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS csf_subcategories (
      id SERIAL PRIMARY KEY,
      subcategory_id      VARCHAR(20)  UNIQUE NOT NULL,
      title               TEXT,
      nist_function       VARCHAR(50)  NOT NULL,
      function_code       VARCHAR(10),
      category_name       VARCHAR(255),
      category_code       VARCHAR(20),
      outcome_description TEXT,
      current_tier        INTEGER,
      target_tier         INTEGER,
      gap                 INTEGER,
      risk_score          INTEGER,
      risk_level          VARCHAR(20),
      primary_owner       VARCHAR(255),
      stakeholders        TEXT,
      tools               TEXT,
      control_links       TEXT,
      status              VARCHAR(50),
      target_date         VARCHAR(20),
      notes               TEXT,
      created_at          TIMESTAMP DEFAULT NOW(),
      updated_at          TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`ALTER TABLE csf_subcategories ADD COLUMN IF NOT EXISTS title TEXT`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS csf_scope_subcategories (
      subcategory_id   VARCHAR(20) PRIMARY KEY,
      scope_status     VARCHAR(20) NOT NULL DEFAULT 'undecided',
      exclusion_reason TEXT,
      created_at       TIMESTAMP DEFAULT NOW(),
      updated_at       TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS scope_departments (
      id                SERIAL PRIMARY KEY,
      department_name   VARCHAR(255) UNIQUE NOT NULL,
      owner_name        VARCHAR(255),
      criticality       VARCHAR(20) DEFAULT 'Medium',
      status            VARCHAR(50) DEFAULT 'Active',
      notes             TEXT,
      created_at        TIMESTAMP DEFAULT NOW(),
      updated_at        TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS assessment_scope_settings (
      id                              INTEGER PRIMARY KEY DEFAULT 1,
      assessment_name                 TEXT NOT NULL DEFAULT '2026 SME Cybersecurity Risk Assessment',
      assessment_type                 VARCHAR(50) NOT NULL DEFAULT 'Asset-based',
      selected_department_ids         INTEGER[] NOT NULL DEFAULT '{}',
      selected_business_process_ids   INTEGER[] NOT NULL DEFAULT '{}',
      selected_asset_ids              INTEGER[] NOT NULL DEFAULT '{}',
      status                          VARCHAR(50) NOT NULL DEFAULT 'Draft',
      created_at                      TIMESTAMP DEFAULT NOW(),
      updated_at                      TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    INSERT INTO assessment_scope_settings (id)
    VALUES (1)
    ON CONFLICT (id) DO NOTHING
  `);

  await ensureBusinessProcessSchema();

  // Remove legacy English placeholder departments (seeded from assets in older schema)
  await pool.query(`
    DELETE FROM scope_departments
     WHERE department_name IN (
       'Engineering', 'Infrastructure', 'IT', 'Product', 'Security'
     )
  `);

  // Seed the 9 standard Mongolian departments (idempotent)
  await pool.query(`
    INSERT INTO scope_departments (department_name, criticality, status) VALUES
      ('Мэдээллийн технологийн хэлтэс',               'High',   'Active'),
      ('Санхүүгийн хэлтэс',                            'High',   'Active'),
      ('Хүний нөөцийн хэлтэс',                         'Medium', 'Active'),
      ('Үйл ажиллагааны хэлтэс',                       'High',   'Active'),
      ('Маркетингийн хэлтэс',                          'Medium', 'Active'),
      ('Худалдан авалт / Нийлүүлэгчийн удирдлагын хэлтэс', 'Medium', 'Active'),
      ('Удирдлага',                                    'High',   'Active'),
      ('Хууль / Нийцлийн хэлтэс',                     'Medium', 'Active'),
      ('Харилцагчийн үйлчилгээний хэлтэс',             'Low',    'Active')
    ON CONFLICT (department_name) DO NOTHING
  `);
}

async function tableExists(tableName: string) {
  const result = await pool.query(
    "SELECT to_regclass($1) IS NOT NULL AS exists",
    [`public.${tableName}`],
  );
  return Boolean(result.rows[0]?.exists);
}

function normalizeIdArray(value: unknown) {
  if (!Array.isArray(value)) return [];
  return Array.from(
    new Set(
      value
        .map((item) => Number(item))
        .filter((item) => Number.isInteger(item) && item > 0),
    ),
  );
}

function normalizePgIdArray(value: unknown) {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => Number(item))
    .filter((item) => Number.isInteger(item) && item > 0);
}

function textOrDefault(value: unknown, fallback: string) {
  const text = textOrEmpty(value);
  return text || fallback;
}

function isHighCriticality(value: string | null | undefined) {
  const normalized = String(value ?? "").toLowerCase();
  return (
    normalized.includes("tier 0") ||
    normalized.includes("tier 1") ||
    normalized === "critical" ||
    normalized === "high"
  );
}

async function getAssessmentScopeSettings(): Promise<AssessmentScopeSettings> {
  const result = await pool.query<{
    id: number;
    assessment_name: string | null;
    assessment_type: string | null;
    selected_department_ids: unknown;
    selected_business_process_ids: unknown;
    selected_asset_ids: unknown;
    status: string | null;
    updated_at: string | null;
  }>(`
    SELECT id, assessment_name, assessment_type, selected_department_ids,
           selected_business_process_ids, selected_asset_ids, status, updated_at
      FROM assessment_scope_settings
     WHERE id = 1
  `);

  const row = result.rows[0];
  return {
    id: Number(row?.id ?? 1),
    assessment_name:
      row?.assessment_name ?? "2026 SME Cybersecurity Risk Assessment",
    assessment_type: row?.assessment_type ?? "Asset-based",
    selected_department_ids: normalizePgIdArray(row?.selected_department_ids),
    selected_business_process_ids: normalizePgIdArray(
      row?.selected_business_process_ids,
    ),
    selected_asset_ids: normalizePgIdArray(row?.selected_asset_ids),
    status: row?.status ?? "Draft",
    updated_at: row?.updated_at ?? null,
  };
}

async function getScopeDepartments() {
  const departments = await pool.query<{
    id: number;
    department_name: string;
    owner_name: string | null;
    criticality: string | null;
    status: string | null;
    notes: string | null;
    updated_at: string | null;
  }>(`
    SELECT id, department_name, owner_name, criticality, status, notes, updated_at
      FROM scope_departments
     ORDER BY department_name ASC
  `);

  const assetCounts = new Map<string, number>();
  if (await tableExists("assets")) {
    const result = await pool.query<{ department: string; count: number }>(`
      SELECT TRIM(department) AS department, COUNT(*)::int AS count
        FROM assets
       WHERE department IS NOT NULL
         AND TRIM(department) <> ''
       GROUP BY TRIM(department)
    `);
    for (const row of result.rows) {
      assetCounts.set(row.department.toLowerCase(), Number(row.count));
    }
  }

  const processCounts = new Map<string, number>();
  const processResult = await pool.query<{
    business_function: string;
    count: number;
  }>(`
    SELECT TRIM(business_function) AS business_function, COUNT(*)::int AS count
      FROM business_processes
     WHERE business_function IS NOT NULL
       AND TRIM(business_function) <> ''
     GROUP BY TRIM(business_function)
  `);
  for (const row of processResult.rows) {
    processCounts.set(row.business_function.toLowerCase(), Number(row.count));
  }

  return departments.rows.map((row) => {
    const key = row.department_name.toLowerCase();
    return {
      ...row,
      asset_count: assetCounts.get(key) ?? 0,
      process_count: processCounts.get(key) ?? 0,
    };
  });
}

async function getScopeBusinessProcesses() {
  const hasAssets = await tableExists("assets");
  const linkedAssetsSql = hasAssets
    ? `COALESCE(
        (SELECT json_agg(
                  json_build_object(
                    'asset_id', bpa.asset_id,
                    'asset_name', a.asset_name,
                    'asset_type', a.asset_type,
                    'criticality', a.criticality,
                    'department', a.department,
                    'dependency_type', bpa.dependency_type
                  )
                  ORDER BY a.asset_name
                )
           FROM business_process_assets bpa
           JOIN assets a ON a.id = bpa.asset_id
          WHERE bpa.business_process_id = bp.id),
        '[]'::json
      ) AS linked_assets`
    : `'[]'::json AS linked_assets`;

  const result = await pool.query(`
    SELECT
      bp.id,
      bp.process_code,
      bp.process_name,
      bp.description,
      bp.business_function,
      bp.business_owner,
      bp.criticality,
      bp.status,
      bp.rto_hours,
      bp.rpo_hours,
      (SELECT COUNT(*)::int
         FROM business_process_assets bpa
        WHERE bpa.business_process_id = bp.id) AS asset_count,
      ${linkedAssetsSql}
    FROM business_processes bp
    ORDER BY
      CASE LOWER(bp.criticality)
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
      END,
      bp.process_name ASC
  `);

  return result.rows;
}

async function getScopeAssets(): Promise<ScopeInventoryAsset[]> {
  if (!(await tableExists("assets"))) return [];

  const result = await pool.query<{
    id: number;
    asset_name: string;
    asset_code: string | null;
    asset_type: string | null;
    department: string | null;
    criticality: string | null;
    internet_exposed: boolean | null;
    status: string | null;
    business_owner: string | null;
    technical_owner: string | null;
    business_process_ids: unknown;
  }>(`
    SELECT
      a.id,
      a.asset_name,
      a.asset_code,
      a.asset_type,
      a.department,
      a.criticality,
      COALESCE(a.internet_exposed, FALSE) AS internet_exposed,
      a.status,
      a.business_owner,
      a.technical_owner,
      COALESCE(
        (SELECT array_agg(bpa.business_process_id ORDER BY bpa.business_process_id)
           FROM business_process_assets bpa
          WHERE bpa.asset_id = a.id),
        '{}'
      ) AS business_process_ids
    FROM assets a
    ORDER BY
      CASE
        WHEN LOWER(COALESCE(a.criticality, '')) LIKE '%tier 0%' THEN 1
        WHEN LOWER(COALESCE(a.criticality, '')) LIKE '%tier 1%' THEN 2
        WHEN LOWER(COALESCE(a.criticality, '')) = 'critical' THEN 3
        WHEN LOWER(COALESCE(a.criticality, '')) = 'high' THEN 4
        ELSE 5
      END,
      a.asset_name ASC
  `);

  return result.rows.map((row) => ({
    ...row,
    internet_exposed: Boolean(row.internet_exposed),
    business_process_ids: normalizePgIdArray(row.business_process_ids),
  }));
}

async function buildScopeResponse() {
  await ensureSchema();

  // Load catalog from DB (has Mongolian title + outcome after user translates)
  const catalogResult = await pool.query<{
    subcategory_id: string;
    title: string;
    outcome_description: string;
    nist_function: string;
    function_code: string;
    category_name: string;
    category_code: string;
  }>(`
    SELECT subcategory_id, title, outcome_description,
           nist_function, function_code, category_name, category_code
      FROM csf_subcategories
     ORDER BY function_code, category_code, subcategory_id
  `);

  const catalog: CsfScopeCatalogItem[] = catalogResult.rows.map((row) => {
    const fc = (row.function_code ?? "GV") as CsfFunctionCode;
    const fn = FUNCTION_BY_CODE[fc];
    return {
      code: row.subcategory_id,
      title: row.title ?? row.subcategory_id,
      outcome: row.outcome_description ?? "",
      category_code: row.category_code ?? "",
      category_name: row.category_name ?? "",
      function_code: fc,
      nist_function: fn?.name ?? row.nist_function ?? fc,
      function_name_mn: fn?.name_mn ?? fc,
      is_mandatory: MANDATORY_SUBCATEGORY_IDS.has(row.subcategory_id),
    };
  });

  const savedResult = await pool.query<SavedScopeRow>(`
    SELECT subcategory_id, scope_status, exclusion_reason, updated_at
      FROM csf_scope_subcategories
  `);
  const savedById = new Map(
    savedResult.rows.map((row) => [row.subcategory_id, row]),
  );

  const rows = catalog.map((item) => {
    const saved = savedById.get(item.code);
    const scopeStatus = item.is_mandatory
      ? "in_scope"
      : normalizeScopeStatus(saved?.scope_status);

    return {
      ...item,
      subcategory_id: item.code,
      scope_status: scopeStatus,
      exclusion_reason:
        scopeStatus === "out_of_scope" ? (saved?.exclusion_reason ?? "") : "",
      updated_at: saved?.updated_at ?? null,
    };
  });

  const summary = {
    total: rows.length,
    mandatory: rows.filter((row) => row.is_mandatory).length,
    in_scope: rows.filter((row) => row.scope_status === "in_scope").length,
    out_of_scope: rows.filter((row) => row.scope_status === "out_of_scope")
      .length,
    undecided: rows.filter((row) => row.scope_status === "undecided").length,
    missing_reason: rows.filter(
      (row) =>
        row.scope_status === "out_of_scope" &&
        row.exclusion_reason.trim().length === 0,
    ).length,
  };

  const byFunction = Array.from(
    rows.reduce((acc, row) => {
      const current = acc.get(row.function_code) ?? {
        function_code: row.function_code,
        nist_function: row.nist_function,
        function_name_mn: row.function_name_mn,
        total: 0,
        mandatory: 0,
        in_scope: 0,
        out_of_scope: 0,
        undecided: 0,
      };

      current.total += 1;
      if (row.is_mandatory) current.mandatory += 1;
      if (row.scope_status === "in_scope") current.in_scope += 1;
      if (row.scope_status === "out_of_scope") current.out_of_scope += 1;
      if (row.scope_status === "undecided") current.undecided += 1;
      acc.set(row.function_code, current);
      return acc;
    }, new Map<string, FunctionScopeSummary>()),
  ).map(([, value]) => value);

  const assessmentScope = await getAssessmentScopeSettings();
  const departments = await getScopeDepartments();
  const businessProcesses = await getScopeBusinessProcesses();
  const assets = await getScopeAssets();

  const selectedDepartmentIds = new Set(
    assessmentScope.selected_department_ids,
  );
  const selectedBusinessProcessIds = new Set(
    assessmentScope.selected_business_process_ids,
  );
  const selectedAssetIds = new Set(assessmentScope.selected_asset_ids);
  const selectedAssets = assets.filter((asset) => selectedAssetIds.has(asset.id));
  const selectedFunctions = byFunction
    .filter((item) => item.in_scope > 0)
    .map((item) => item.function_code);

  const scopeSummary = {
    assessment_name: assessmentScope.assessment_name,
    assessment_type: assessmentScope.assessment_type,
    departments_selected: departments.filter((department) =>
      selectedDepartmentIds.has(Number(department.id)),
    ).length,
    business_processes_selected: businessProcesses.filter((process) =>
      selectedBusinessProcessIds.has(Number(process.id)),
    ).length,
    assets_selected: selectedAssets.length,
    critical_assets: selectedAssets.filter((asset) =>
      isHighCriticality(asset.criticality),
    ).length,
    internet_exposed_assets: selectedAssets.filter(
      (asset) => asset.internet_exposed,
    ).length,
    nist_functions: selectedFunctions.length,
    nist_function_codes: selectedFunctions,
    nist_subcategories: summary.in_scope,
    excluded_areas: summary.out_of_scope,
    missing_exclusion_reasons: summary.missing_reason,
    status: assessmentScope.status,
  };

  return {
    rows,
    summary,
    by_function: byFunction,
    assessment_scope: assessmentScope,
    departments,
    business_processes: businessProcesses,
    assets,
    scope_summary: scopeSummary,
  };
}

function textOrEmpty(value: unknown) {
  return typeof value === "string" ? value.trim() : "";
}

async function requireManagement(req: NextRequest) {
  const user = await getCurrentUser(req);
  if (!user) {
    return NextResponse.json(
      { error: "Нэвтэрсэн хэрэглэгч олдсонгүй" },
      { status: 401 },
    );
  }

  if (user.role_id !== ROLE_MANAGER) {
    return NextResponse.json(
      { error: "Зөвхөн удирдлага эрсдэлийн үнэлгээний хамрах хүрээг өөрчлөх эрхтэй" },
      { status: 403 },
    );
  }

  return null;
}

export async function GET() {
  try {
    return NextResponse.json(await buildScopeResponse());
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "fetch failed" },
      { status: 500 },
    );
  }
}

export async function POST(req: NextRequest) {
  const forbidden = await requireManagement(req);
  if (forbidden) return forbidden;

  const client = await pool.connect();
  try {
    await ensureSchema();

    const body = await req.json().catch(() => ({}));
    const updates = Array.isArray(body?.updates)
      ? (body.updates as ScopeUpdate[])
      : [];
    const departmentInput =
      body?.department && typeof body.department === "object"
        ? (body.department as Record<string, unknown>)
        : null;
    const assessmentScopeInput =
      body?.assessment_scope && typeof body.assessment_scope === "object"
        ? (body.assessment_scope as Record<string, unknown>)
        : null;

    if (updates.length === 0 && !departmentInput && !assessmentScopeInput) {
      return NextResponse.json(
        { error: "updates, department, or assessment_scope is required" },
        { status: 400 },
      );
    }

    const normalized: Array<{
      subcategory_id: string;
      scope_status: CsfScopeStatus;
      exclusion_reason: string | null;
    }> = [];
    const missingReasons: string[] = [];

    if (updates.length > 0) {
      const catalogDbResult = await pool.query<{ subcategory_id: string }>(
        `SELECT subcategory_id FROM csf_subcategories`,
      );
      const catalogById = new Map(
        catalogDbResult.rows.map((r) => [
          r.subcategory_id,
          {
            code: r.subcategory_id,
            is_mandatory: MANDATORY_SUBCATEGORY_IDS.has(r.subcategory_id),
          },
        ]),
      );

      for (const update of updates) {
        const subcategoryId = textOrEmpty(update.subcategory_id).toUpperCase();
        const catalogItem = catalogById.get(subcategoryId);
        if (!catalogItem) continue;

        const scopeStatus = catalogItem.is_mandatory
          ? "in_scope"
          : normalizeScopeStatus(update.scope_status);
        const exclusionReason = textOrEmpty(update.exclusion_reason);

        if (scopeStatus === "out_of_scope" && !exclusionReason) {
          missingReasons.push(subcategoryId);
          continue;
        }

        normalized.push({
          subcategory_id: subcategoryId,
          scope_status: scopeStatus,
          exclusion_reason:
            scopeStatus === "out_of_scope" ? exclusionReason : null,
        });
      }
    }

    if (missingReasons.length > 0) {
      return NextResponse.json(
        {
          error: "exclusion_reason required for out_of_scope subcategories",
          missing_reasons: missingReasons,
        },
        { status: 400 },
      );
    }

    await client.query("BEGIN");

    if (departmentInput) {
      const departmentName = textOrEmpty(departmentInput.department_name);
      if (!departmentName) {
        await client.query("ROLLBACK");
        return NextResponse.json(
          { error: "department_name is required" },
          { status: 400 },
        );
      }

      await client.query(
        `INSERT INTO scope_departments
           (department_name, owner_name, criticality, status, notes, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW())
         ON CONFLICT (department_name) DO UPDATE SET
           owner_name = EXCLUDED.owner_name,
           criticality = EXCLUDED.criticality,
           status = EXCLUDED.status,
           notes = EXCLUDED.notes,
           updated_at = NOW()`,
        [
          departmentName,
          textOrEmpty(departmentInput.owner_name) || null,
          textOrDefault(departmentInput.criticality, "Medium"),
          textOrDefault(departmentInput.status, "Active"),
          textOrEmpty(departmentInput.notes) || null,
        ],
      );
    }

    for (const row of normalized) {
      await client.query(
        `INSERT INTO csf_scope_subcategories
           (subcategory_id, scope_status, exclusion_reason, updated_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (subcategory_id) DO UPDATE SET
           scope_status = EXCLUDED.scope_status,
           exclusion_reason = EXCLUDED.exclusion_reason,
           updated_at = NOW()`,
        [row.subcategory_id, row.scope_status, row.exclusion_reason],
      );
    }

    if (assessmentScopeInput) {
      await client.query(
        `INSERT INTO assessment_scope_settings
           (id, assessment_name, assessment_type, selected_department_ids,
            selected_business_process_ids, selected_asset_ids, status, updated_at)
         VALUES (1, $1, $2, $3::int[], $4::int[], $5::int[], $6, NOW())
         ON CONFLICT (id) DO UPDATE SET
           assessment_name = EXCLUDED.assessment_name,
           assessment_type = EXCLUDED.assessment_type,
           selected_department_ids = EXCLUDED.selected_department_ids,
           selected_business_process_ids = EXCLUDED.selected_business_process_ids,
           selected_asset_ids = EXCLUDED.selected_asset_ids,
           status = EXCLUDED.status,
           updated_at = NOW()`,
        [
          textOrDefault(
            assessmentScopeInput.assessment_name,
            "2026 SME Cybersecurity Risk Assessment",
          ),
          textOrDefault(assessmentScopeInput.assessment_type, "Asset-based"),
          normalizeIdArray(assessmentScopeInput.selected_department_ids),
          normalizeIdArray(
            assessmentScopeInput.selected_business_process_ids,
          ),
          normalizeIdArray(assessmentScopeInput.selected_asset_ids),
          textOrDefault(assessmentScopeInput.status, "Draft"),
        ],
      );
    }

    await client.query("COMMIT");

    return NextResponse.json(await buildScopeResponse());
  } catch (error) {
    await client.query("ROLLBACK");
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "save failed" },
      { status: 500 },
    );
  } finally {
    client.release();
  }
}

export async function DELETE(req: NextRequest) {
  try {
    const forbidden = await requireManagement(req);
    if (forbidden) return forbidden;

    await ensureSchema();
    const { searchParams } = new URL(req.url);
    const departmentId = Number(searchParams.get("department_id"));
    if (!Number.isFinite(departmentId) || departmentId <= 0) {
      return NextResponse.json({ error: "department_id is required" }, { status: 400 });
    }
    await pool.query(`DELETE FROM scope_departments WHERE id = $1`, [departmentId]);
    return NextResponse.json({ success: true });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "delete failed" },
      { status: 500 },
    );
  }
}
