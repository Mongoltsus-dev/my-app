import { pool } from "@/lib/db";
import bcrypt from "bcrypt";
import { NextRequest, NextResponse } from "next/server";

interface LoginRequest {
  email?: string;
  password?: string;
  riskAssessment?: unknown;
  userAgent?: string;
}

export async function POST(request: NextRequest) {
  try {
    const body: LoginRequest = await request.json();
    const { email, password } = body;

    if (!email || !password) {
      return NextResponse.json(
        { message: "Email and password are required" },
        { status: 400 },
      );
    }

    // Fetch user from database
    const normalizedEmail = email.toLowerCase();

    const result = await pool.query(
      "SELECT id, full_name, email, role_id, status, password_hash FROM users WHERE email = $1",
      [normalizedEmail],
    );

    if (result.rows.length === 0) {
      return NextResponse.json(
        { message: "Invalid email or password" },
        { status: 401 },
      );
    }

    const userData = result.rows[0];

    if (userData.status !== "active") {
      return NextResponse.json(
        { message: `Account is ${userData.status}` },
        { status: 403 },
      );
    }

    const passwordValid = await bcrypt.compare(
      password,
      userData.password_hash,
    );

    if (!passwordValid) {
      return NextResponse.json(
        { message: "Invalid email or password" },
        { status: 401 },
      );
    }

    // TODO: Implement risk score calculation from database
    const userRiskScore = 0; // Placeholder

    // TODO: Implement MFA logic and database storage
    // if (userData.mfa_enabled || riskAssessment?.riskScore >= 75) {
    //   // MFA logic here
    // }

    // TODO: Log successful login to database
    // TODO: Update last login timestamp in database

    const response = NextResponse.json(
      {
        message: "Login successful",
        user: {
          user_id: userData.id,
          name: userData.full_name,
          email: userData.email,
          role: userData.role_id,
          riskScore: userRiskScore,
        },
      },
      { status: 200 },
    );

    const isHttps =
      request.nextUrl.protocol === "https:" ||
      request.headers.get("x-forwarded-proto") === "https";

    // Set secure cookies
    response.cookies.set({
      name: "accessToken",
      value: `token_${userData.id}`,
      httpOnly: true,
      secure: isHttps,
      sameSite: "strict",
      path: "/",
      maxAge: 3600,
    });

    return response;
  } catch (error) {
    console.error("Login error:", error);
    return NextResponse.json(
      { message: "Internal server error" },
      { status: 500 },
    );
  }
}

// TODO: Implement logAuditEvent function with database integration
