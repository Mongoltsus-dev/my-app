import { NextResponse } from "next/server";

const DISABLED_RESPONSE = {
  message:
    "Public registration is disabled. User access must be created by a system administrator.",
};

export async function GET() {
  return NextResponse.json(DISABLED_RESPONSE, { status: 410 });
}

export async function POST() {
  return NextResponse.json(DISABLED_RESPONSE, { status: 410 });
}
