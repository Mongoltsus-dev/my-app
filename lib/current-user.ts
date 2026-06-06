import { pool } from "@/lib/db";
import { type NextRequest } from "next/server";

export const ROLE_MANAGER = 2;
export const MANAGEMENT_APPROVER_LABEL = "удирдлага";

export type CurrentUser = {
  id: number;
  full_name: string;
  email: string;
  role_id: number;
  status: string;
};

function userIdFromAccessToken(req: NextRequest) {
  const token = req.cookies.get("accessToken")?.value ?? "";
  const match = /^token_(\d+)$/.exec(token);
  if (!match) return null;

  const userId = Number(match[1]);
  return Number.isInteger(userId) && userId > 0 ? userId : null;
}

export async function getCurrentUser(req: NextRequest) {
  const userId = userIdFromAccessToken(req);
  if (!userId) return null;

  const result = await pool.query<CurrentUser>(
    `SELECT id, full_name, email, role_id, status
       FROM users
      WHERE id = $1
        AND status = 'active'`,
    [userId],
  );

  return result.rows[0] ?? null;
}
