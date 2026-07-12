// app/api/products/search/route.js
//
// ⚠️ INTENTIONALLY VULNERABLE — TRAINING/TESTING USE ONLY ⚠️
//
// VULNERABILITY: classic SQL injection. The search term is concatenated
// directly into the SQL string instead of using a parameterized query
// (compare to lib/db.js, which uses `?` placeholders correctly elsewhere).
//
// Try, e.g.:
//   GET /api/products/search?q=Mouse
//   GET /api/products/search?q=' OR '1'='1
//   GET /api/products/search?q=' UNION SELECT id,email,password,1 FROM users --
//
// A real app must use `db.prepare("... WHERE name LIKE ?").all(`%${q}%`)`.

import db from "@/lib/db";
import { NextResponse } from "next/server";

export async function GET(req) {
  const { searchParams } = new URL(req.url);
  const q = searchParams.get("q") || "";

  const sql = `SELECT id, name, description, price FROM products WHERE name LIKE '%${q}%'`;

  try {
    const results = db.prepare(sql).all();
    return NextResponse.json({ results, sql }); // sql echoed back on purpose for the demo/lesson
  } catch (err) {
    return NextResponse.json({ error: err.message, sql }, { status: 500 });
  }
}
