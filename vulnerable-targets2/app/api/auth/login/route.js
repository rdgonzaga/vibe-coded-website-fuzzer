import { getUser } from "../../../../lib/db";
import { signToken } from "../../../../lib/auth";

export async function POST(req) {
  const { email, password } = await req.json();
  const user = getUser(email);

  // VULNERABLE: plaintext password comparison, no hashing
  if (user && user.password === password) {
    return Response.json({ token: signToken(user) });
  }
  return new Response("Unauthorized", { status: 401 });
}
