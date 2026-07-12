// app/api/auth/login/route.js
//
// ⚠️ INTENTIONALLY VULNERABLE — TRAINING/TESTING USE ONLY ⚠️
//
// This endpoint has NO rate limiting or account lockout by design, so it
// can be used to practice/demonstrate credential-stuffing and brute-force
// attacks (e.g. with a tool like Hydra, Burp Intruder, or a simple script)
// against a safe, local, throwaway target instead of a real service.
//
// A production login endpoint should have, at minimum:
//   - Per-IP and per-account rate limiting / exponential backoff
//   - Account lockout or CAPTCHA after repeated failures
//   - Constant-time password comparison (bcrypt/argon2 compare, not ===)
//   - Generic error messages that don't reveal whether the email exists

import db from "@/lib/db";
import { signToken } from "@/lib/auth";
import { NextResponse } from "next/server";

export async function POST(req) {
  const { email, password } = await req.json();

  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

  // VULNERABILITY: user enumeration — the two failure cases are
  // distinguishable ("no such user" vs "wrong password"), so an attacker can
  // tell which emails are registered.
  if (!user) {
    return NextResponse.json({ error: "No account with that email" }, { status: 401 });
  }

  // VULNERABILITY: plaintext, non-constant-time password comparison.
  if (user.password !== password) {
    return NextResponse.json({ error: "Incorrect password" }, { status: 401 });
  }

  const token = signToken(user);

  // VULNERABILITY: no rate limiting / lockout anywhere in this handler —
  // this endpoint can be hammered with unlimited login attempts per second.

  return NextResponse.json({
    token,
    user: { id: user.id, email: user.email, name: user.name, is_admin: user.is_admin },
  });
}
