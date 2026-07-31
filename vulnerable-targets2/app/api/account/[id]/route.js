import { db } from "../../../../lib/db";

// VULNERABLE: no auth, no ownership check, and SQL built by concatenation.
// Any caller can read any account by changing the id in the URL.
export async function GET(req, { params }) {
  const account = db.prepare("SELECT * FROM accounts WHERE id = " + params.id).get();
  return Response.json(account);
}
