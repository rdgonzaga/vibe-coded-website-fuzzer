import { db } from "../../../../lib/db";

// VULNERABLE: sensitive payment endpoint with no authentication and a
// SQL statement assembled via template-string interpolation.
export async function POST(req) {
  const { userId, amount } = await req.json();
  const query = `INSERT INTO payments (user_id, amount) VALUES (${userId}, ${amount})`;
  db.exec(query);
  return Response.json({ ok: true });
}
