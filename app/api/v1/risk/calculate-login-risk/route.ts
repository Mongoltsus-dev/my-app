import { NextRequest, NextResponse } from "next/server";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { email, timestamp, userAgent } = body;
    const currentIp =
      request.headers.get("x-forwarded-for") ||
      request.headers.get("x-real-ip") ||
      "unknown";

    let riskScore = 0;
    const riskFactors: string[] = [];

    // TODO: Fetch failed login attempts from database
    const failureCount = 0;
    if (failureCount > 3) {
      riskScore += 20;
      riskFactors.push("Multiple recent failed login attempts");
    }

    // TODO: Fetch last login IP from database
    // if (lastLogin.rows.length > 0) {
    //   const lastIp = lastLogin.rows[0].ip_address;
    //   if (lastIp !== currentIp) {
    //     riskScore += 15;
    //     riskFactors.push("Login from different IP address");
    //   }
    // }

    // Check for unusual time
    const hourOfDay = new Date(timestamp).getHours();
    if (hourOfDay < 6 || hourOfDay > 22) {
      riskScore += 10;
      riskFactors.push("Login attempt outside business hours");
    }

    // TODO: Fetch known user agents from database
    // const knownUserAgents = previousUserAgents.rows.map((r: any) => r.user_agent);
    // if (knownUserAgents.length > 0 && !knownUserAgents.includes(userAgent)) {
    //   riskScore += 10;
    //   riskFactors.push("Login from new device or browser");
    // }

    riskScore = Math.min(Math.max(riskScore, 0), 100);

    let riskTier: "critical" | "high" | "medium" | "low";
    let recommendation: string;

    if (riskScore >= 75) {
      riskTier = "critical";
      recommendation =
        "This login attempt poses critical risk. Multi-factor authentication is required.";
    } else if (riskScore >= 50) {
      riskTier = "high";
      recommendation =
        "Elevated risk detected. Multi-factor authentication may be required.";
    } else if (riskScore >= 25) {
      riskTier = "medium";
      recommendation = "Moderate risk indicators present.";
    } else {
      riskTier = "low";
      recommendation = "Login appears normal.";
    }

    return NextResponse.json({
      riskScore: Math.round(riskScore * 100) / 100,
      riskTier,
      recommendation,
      factors: riskFactors,
    });
  } catch (error) {
    console.error("Risk calculation error:", error);
    return NextResponse.json(
      {
        riskScore: 0,
        riskTier: "low",
        recommendation: "",
        factors: [],
      },
      { status: 200 },
    );
  }
}
