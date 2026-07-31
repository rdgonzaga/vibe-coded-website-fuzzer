import { db } from "../../../../lib/db";

// VULNERABLE: no auth, and password change gated on a plaintext comparison.
// The SELECT/UPDATE are parameterized on purpose — the scanner should NOT
// flag SQL injection here, only the missing auth and plaintext compare.
export async function POST(req) {
  const { userId, oldPassword, newPassword } = await req.json();
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);

  if (user && user.password == oldPassword) {
    db.prepare("UPDATE users SET password = ? WHERE id = ?").run(newPassword, userId);
    return Response.json({ ok: true });
  }
  return new Response("Forbidden", { status: 403 });
}
