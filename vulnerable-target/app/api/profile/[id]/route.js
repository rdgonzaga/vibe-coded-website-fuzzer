// app/api/profile/[id]/route.js
//
// ⚠️ INTENTIONALLY VULNERABLE — TRAINING/TESTING USE ONLY ⚠️
//
// VULNERABILITY: Broken Object Level Authorization (BOLA/IDOR). The route
// only checks that *some* valid JWT was supplied — it never checks that the
// logged-in user's id matches the :id in the URL. So any logged-in user
// (alice) can read/edit bob's profile just by changing the URL:
//   GET /api/profile/1   (alice, her own profile — fine)
//   GET /api/profile/2   (alice viewing bob's profile — should be blocked, isn't)
//
// A real app must check `payload.id === Number(id)` (or an admin role)
// before returning/updating another user's data.

import db from "@/lib/db";
import { verifyToken } from "@/lib/auth";
import { NextResponse } from "next/server";

function getPayload(req) {
  const authHeader = req.headers.get("authorization") || "";
  const token = authHeader.replace(/^Bearer\s+/i, "");
  return verifyToken(token);
}

export async function GET(req, { params }) {
  const payload = getPayload(req);
  if (!payload) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;

  // VULNERABILITY: `id` is trusted directly with no ownership check
  // against `payload.id`.
  const user = db
    .prepare("SELECT id, email, name, address, is_admin FROM users WHERE id = ?")
    .get(id);

  if (!user) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  return NextResponse.json({ user });
}

export async function PUT(req, { params }) {
  const payload = getPayload(req);
  if (!payload) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json();
  const { id } = await params;

  // VULNERABILITY: same missing ownership check on writes — any logged-in
  // user can overwrite any other user's name/address, and even flip
  // `is_admin` on their own or someone else's account since it's accepted
  // straight from the request body (mass assignment).
  db.prepare(
    "UPDATE users SET name = ?, address = ?, is_admin = ? WHERE id = ?"
  ).run(body.name, body.address, body.is_admin ? 1 : 0, id);

  return NextResponse.json({ ok: true });
}
