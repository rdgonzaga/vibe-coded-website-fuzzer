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
    <div className="page page-wide">
      <h1 className="page-title">Products</h1>
      <p className="page-subtitle">Search the catalog below.</p>
      <form onSubmit={search} className="search-bar">
        <input
          placeholder="Search products..."
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <button type="submit">Search</button>
      </form>
      {sql && (
        <div className="sql-preview">
          Executed SQL (shown for the demo): <code>{sql}</code>
        </div>
      )}
      {error && <div className="alert alert-error">{error}</div>}
      <ul className="result-list">
        {results.map((p) => (
          <li key={p.id ?? JSON.stringify(p)} className="result-row">
            {JSON.stringify(p)}
          </li>
        ))}
      </ul>
    </div>
  );
}
