import { pool } from "@/lib/db";
import { NextRequest, NextResponse } from "next/server";

async function tableExists(tableName: string) {
  const result = await pool.query("SELECT to_regclass($1) AS name", [
    tableName,
  ]);
  return Boolean(result.rows[0]?.name);
}

// GET - Fetch recommended NIST controls for a risk
export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const riskAnalysisId = searchParams.get("risk_analysis_id");
    const riskRegisterId = searchParams.get("risk_register_id");
    const riskLevel = searchParams.get("risk_level");
    const hasRecommendations = await tableExists("control_recommendations");
    const hasNistControls = await tableExists("nist_controls");

    if (!hasRecommendations || !hasNistControls) {
      return NextResponse.json({ recommendations: [], count: 0 });
    }

    let query = `
        SELECT cr.*, nc.domain, nc.control_name AS catalog_control_name, nc.description
        FROM control_recommendations cr
        LEFT JOIN nist_controls nc ON cr.control_id = nc.control_id
        WHERE 1=1
      `;
    const params: any[] = [];

    if (riskAnalysisId) {
      query += ` AND cr.risk_analysis_id = $${params.length + 1}`;
      params.push(riskAnalysisId);
    }

    if (riskRegisterId) {
      query += ` AND cr.risk_register_id = $${params.length + 1}`;
      params.push(riskRegisterId);
    }

    if (riskLevel) {
      // Filter by implementation priority based on risk level
      if (riskLevel === "Critical") {
        query += ` AND (cr.implementation_priority IN ('Critical', 'High'))`;
      } else if (riskLevel === "High") {
        query += ` AND (cr.implementation_priority IN ('High', 'Medium'))`;
      }
    }

    query += ` ORDER BY
      CASE cr.implementation_priority
        WHEN 'Critical' THEN 1
        WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3
        ELSE 4
      END`;

    query += `, nc.priority ASC`;

    query += ` LIMIT 10`;

    const result = await pool.query(query, params);

    return NextResponse.json({
      recommendations: result.rows || [],
      count: result.rows?.length || 0,
    });
  } catch (err: any) {
    console.error("Error fetching control recommendations:", err);
    return NextResponse.json(
      { error: "Failed to fetch control recommendations" },
      { status: 500 },
    );
  }
}

// POST - Generate control recommendations based on risk analysis
export async function POST(req: NextRequest) {
  try {
    const { risk_analysis_id, risk_register_id } = await req.json();

    if (!risk_analysis_id || !risk_register_id) {
      return NextResponse.json(
        { error: "risk_analysis_id and risk_register_id are required" },
        { status: 400 },
      );
    }

    // Get risk analysis details
    const analysisResult = await pool.query(
      `SELECT ra.*, rr.nist_csf_function, rr.asset_id, a.asset_type
       FROM risk_analysis ra
       LEFT JOIN risk_register rr ON ra.risk_id = rr.id
       LEFT JOIN assets a ON rr.asset_id = a.id
       WHERE ra.id = $1`,
      [risk_analysis_id],
    );

    if (analysisResult.rows.length === 0) {
      return NextResponse.json(
        { error: "Risk analysis not found" },
        { status: 404 },
      );
    }

    const analysis = analysisResult.rows[0];
    const riskLevel = analysis.risk_level;
    const nistFunction = analysis.nist_csf_function || "Identify";

    // Determine priority based on risk level
    const determinePriority = (level: string): string => {
      if (level === "Critical") return "Critical";
      if (level === "High") return "High";
      if (level === "Medium") return "Medium";
      return "Low";
    };

    const priority = determinePriority(riskLevel);

    const hasNistControls = await tableExists("nist_controls");
    if (!hasNistControls) {
      return NextResponse.json({
        message:
          "NIST control catalog is not available; use NIST CSF control objectives instead.",
        count: 0,
        recommendations: [],
        context: {
          riskLevel: riskLevel,
          nistFunction: nistFunction,
          recommendedPriority: priority,
        },
      });
    }

    // Find relevant NIST controls
    // Strategy: Match by NIST CSF function first, then by risk level priority
    const controlsResult = await pool.query(
      `SELECT * FROM nist_controls
       WHERE nist_csf_function = $1
         AND is_active = true
       ORDER BY priority ASC
       LIMIT 10`,
      [nistFunction],
    );

    const controls = controlsResult.rows || [];

    // Generate recommendations
    const recommendations = [];
    const seenControlIds = new Set();

    for (const control of controls) {
      if (seenControlIds.has(control.control_id)) continue;
      seenControlIds.add(control.control_id);

      // Check if recommendation already exists
      const existingResult = await pool.query(
        `SELECT id FROM control_recommendations
         WHERE risk_analysis_id = $1 AND control_id = $2`,
        [risk_analysis_id, control.control_id],
      );

      if (existingResult.rows.length === 0) {
        // Insert new recommendation
        const insertResult = await pool.query(
          `INSERT INTO control_recommendations (
            risk_analysis_id, risk_register_id, control_id, domain,
            implementation_priority, recommendation_rationale, created_at, updated_at
          ) VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
          RETURNING *`,
          [
            risk_analysis_id,
            risk_register_id,
            control.control_id,
            control.domain,
            priority,
            `Recommended to address ${riskLevel}-level risk in ${nistFunction} function. ${control.implementation_note || ""}`,
          ],
        );
        recommendations.push(insertResult.rows[0]);
      }
    }

    return NextResponse.json({
      message: "Control recommendations generated successfully",
      count: recommendations.length,
      recommendations: recommendations,
      context: {
        riskLevel: riskLevel,
        nistFunction: nistFunction,
        recommendedPriority: priority,
      },
    });
  } catch (error: unknown) /* eslint-disable-line @typescript-eslint/no-explicit-any */ {
    console.error("Control recommendation error:", error);
    return NextResponse.json(
      {
        error:
          error instanceof Error
            ? error.message
            : "Failed to generate recommendations",
      },
      { status: 500 },
    );
  }
}

// PUT - Update control recommendation status
export async function PUT(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const controlRecId = searchParams.get("id");

    if (!controlRecId) {
      return NextResponse.json(
        { error: "Control recommendation ID is required" },
        { status: 400 },
      );
    }

    const {
      implementation_status,
      assigned_to,
      target_implementation_date,
      actual_implementation_date,
      notes,
    } = await req.json();

    const result = await pool.query(
      `UPDATE control_recommendations SET
        implementation_status = COALESCE($1, implementation_status),
        assigned_to = COALESCE($2, assigned_to),
        target_implementation_date = COALESCE($3, target_implementation_date),
        actual_implementation_date = COALESCE($4, actual_implementation_date),
        notes = COALESCE($5, notes),
        updated_at = CURRENT_TIMESTAMP
       WHERE id = $6
       RETURNING *`,
      [
        implementation_status || null,
        assigned_to || null,
        target_implementation_date || null,
        actual_implementation_date || null,
        notes || null,
        controlRecId,
      ],
    );

    if (result.rows.length === 0) {
      return NextResponse.json(
        { error: "Control recommendation not found" },
        { status: 404 },
      );
    }

    return NextResponse.json({
      message: "Control recommendation updated successfully",
      recommendation: result.rows[0],
    });
  } catch (error: unknown) /* eslint-disable-line @typescript-eslint/no-explicit-any */ {
    console.error("Control recommendation update error:", error);
    return NextResponse.json(
      {
        error:
          error instanceof Error
            ? error.message
            : "Failed to update control recommendation",
      },
      { status: 500 },
    );
  }
}
