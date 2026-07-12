"use client";

// app/products/page.js
// ⚠️ INTENTIONALLY VULNERABLE — TRAINING/TESTING USE ONLY ⚠️
// The search box below hits /api/products/search, which is SQL-injectable.
// Try: ' OR '1'='1   or   ' UNION SELECT id,email,password,1 FROM users --

import { useState } from "react";

export default function ProductsPage() {
  const [q, setQ] = useState("");
  const [results, setResults] = useState([]);
  const [sql, setSql] = useState("");
  const [error, setError] = useState("");

  async function search(e) {
    e.preventDefault();
    setError("");
    const res = await fetch(`/api/products/search?q=${encodeURIComponent(q)}`);
    const data = await res.json();
    if (!res.ok) {
      setError(data.error);
      setSql(data.sql || "");
      return;
    }
    setResults(data.results);
    setSql(data.sql);
  }

  return (
    <main style={{ maxWidth: 640, margin: "80px auto", fontFamily: "sans-serif" }}>
      <h1>Products</h1>
      <form onSubmit={search} style={{ marginBottom: 16 }}>
        <input
          style={{ width: "70%", padding: 8 }}
          placeholder="Search products..."
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <button style={{ padding: 8, marginLeft: 8 }} type="submit">
          Search
        </button>
      </form>
      {sql && (
        <p style={{ fontSize: 12, color: "#888" }}>
          Executed SQL (shown for the demo): <code>{sql}</code>
        </p>
      )}
      {error && <p style={{ color: "red" }}>{error}</p>}
      <ul>
        {results.map((p) => (
          <li key={p.id ?? JSON.stringify(p)}>
            {JSON.stringify(p)}
          </li>
        ))}
      </ul>
    </main>
  );
}
