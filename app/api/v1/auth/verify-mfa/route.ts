import { NextRequest, NextResponse } from "next/server";

export async function POST(request: NextRequest) {
  try {
    const body = (await request.json()) as { mfaCode?: unknown };
    const { mfaCode } = body;

    // Verify MFA code (in production, validate properly)
    if (typeof mfaCode !== "string" || mfaCode.length !== 6) {
      return NextResponse.json(
        { message: "Invalid MFA code format" },
        { status: 400 },
      );
    }

    // TODO: Verify MFA token and fetch user from database
    // Placeholder implementation
    const userData = {
      user_id: "placeholder",
      email: "placeholder@example.com",
      role: "user",
      assigned_assets: [],
    };
    // TODO: Delete MFA code from database

    const response = NextResponse.json(
      {
        message: "MFA verification successful",
        user: {
          user_id: userData.user_id,
          email: userData.email,
          role: userData.role,
          assignedAssets: userData.assigned_assets,
        },
      },
      { status: 200 },
    );

    const isHttps =
      request.nextUrl.protocol === "https:" ||
      request.headers.get("x-forwarded-proto") === "https";

    response.cookies.set({
      name: "accessToken",
      value: `token_${userData.user_id}`,
      httpOnly: true,
      secure: isHttps,
      sameSite: "strict",
      path: "/",
      maxAge: 3600,
    });

    return response;
  } catch (error) {
    console.error("MFA verification error:", error);
    return NextResponse.json(
      { message: "Internal server error" },
      { status: 500 },
    );
  }
}
