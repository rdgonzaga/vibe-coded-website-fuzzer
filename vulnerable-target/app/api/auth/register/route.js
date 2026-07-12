// app/api/auth/register/route.js
//
// ⚠️ INTENTIONALLY VULNERABLE — TRAINING/TESTING USE ONLY ⚠️

import db from "@/lib/db";
import { signToken } from "@/lib/auth";
import { NextResponse } from "next/server";

export async function POST(req) {
  const body = await req.json();
  const { email, password, name, address } = body;

  // VULNERABILITY: no input validation at all — no email format check,
  // no password strength/length requirement, no length limits (DoS via
  // huge payloads), no check for missing fields before hitting the DB.

  try {
    const insert = db.prepare(
      "INSERT INTO users (email, password, name, address, is_admin) VALUES (?, ?, ?, ?, 0)"
    );
    const info = insert.run(email, password, name, address);

    const user = { id: info.lastInsertRowid, email, is_admin: 0 };
    const token = signToken(user);

    return NextResponse.json({ token, user });
  } catch (err) {
    // VULNERABILITY: raw error/exception details (including stack trace and
    // internal DB error messages) are returned straight to the client. This
    // can leak schema info, file paths, and library versions to an attacker.
    return NextResponse.json(
      { error: "Registration failed", details: err.message, stack: err.stack },
      { status: 500 }
    );
  }
}
