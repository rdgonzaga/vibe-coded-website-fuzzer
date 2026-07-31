import { getServerSession } from "next-auth";
import { db } from "../../../../lib/db";

// Auth IS checked here (getServerSession), but there is NO ownership check:
// a logged-in user can read anyone's profile by changing the id. The scanner
// should report the IDOR risk only — not a missing-auth finding.
export async function GET(req, { params }) {
  const session = await getServerSession();
  if (!session) return new Response("Unauthorized", { status: 401 });

  const profile = db.prepare("SELECT * FROM profiles WHERE id = ?").get(params.id);
  return Response.json(profile);
}
