import { db } from "../../../../lib/db";

// VULNERABLE: admin-only listing with no auth check and a concatenated query.
export async function GET(req) {
  const role = new URL(req.url).searchParams.get("role");
  const users = db.prepare("SELECT * FROM users WHERE role = '" + role + "'").all();
  return Response.json(users);
}
