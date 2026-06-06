import { pool } from "@/lib/db";
import { NextRequest, NextResponse } from "next/server";

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const assetType = searchParams.get("asset_type");

    let query =
      "SELECT * FROM risks ORDER BY nist_csf_function, nist_csf_category";
    let params: any[] = [];

    if (assetType) {
      // Filter risks by asset type (risks with applicable_asset_types containing the asset_type)
      query = `
        SELECT * FROM risks 
        WHERE applicable_asset_types LIKE $1 
        ORDER BY nist_csf_function, nist_csf_category
      `;
      params = [`%${assetType}%`];
    }

    const result = await pool.query(query, params);
    return NextResponse.json({
      risks: result.rows || [],
      count: result.rows?.length || 0,
    });
  } catch (err: any) {
    console.error("Error fetching risks:", err);
    return NextResponse.json(
      { error: "Failed to fetch risks" },
      { status: 500 },
    );
  }
}
