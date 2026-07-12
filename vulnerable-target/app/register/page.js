"use client";

// app/register/page.js
// ⚠️ INTENTIONALLY VULNERABLE — TRAINING/TESTING USE ONLY ⚠️
// See app/api/auth/register/route.js for the missing validation this
// form relies on (no email format check, no password strength rules, etc.)

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function RegisterPage() {
  const [form, setForm] = useState({ email: "", password: "", name: "", address: "" });
  const [error, setError] = useState("");
  const router = useRouter();

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");

    const res = await fetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(form),
    });
    const data = await res.json();

    if (!res.ok) {
      setError(data.details || data.error || "Registration failed");
      return;
    }

    localStorage.setItem("token", data.token);
    localStorage.setItem("user", JSON.stringify(data.user));
    router.push(`/profile?id=${data.user.id}`);
  }

  return (
    <main style={{ maxWidth: 360, margin: "80px auto", fontFamily: "sans-serif" }}>
      <h1>Create account</h1>
      <form onSubmit={handleSubmit}>
        {["email", "password", "name", "address"].map((field) => (
          <div key={field} style={{ marginBottom: 12 }}>
            <label>{field}</label>
            <br />
            <input
              style={{ width: "100%", padding: 8 }}
              type={field === "password" ? "password" : "text"}
              value={form[field]}
              onChange={(e) => setForm({ ...form, [field]: e.target.value })}
            />
          </div>
        ))}
        {error && <p style={{ color: "red" }}>{String(error)}</p>}
        <button style={{ width: "100%", padding: 10 }} type="submit">
          Register
        </button>
      </form>
    </main>
  );
}
