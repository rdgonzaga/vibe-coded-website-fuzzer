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
    <div className="page page-form">
      <div className="card">
        <h1 className="page-title">Create account</h1>
        <p className="page-subtitle">Join Vuln-Shop to start shopping.</p>
        <form onSubmit={handleSubmit}>
          {["email", "password", "name", "address"].map((field) => (
            <div key={field} className="field">
              <label>{field}</label>
              <input
                type={field === "password" ? "password" : "text"}
                value={form[field]}
                onChange={(e) => setForm({ ...form, [field]: e.target.value })}
              />
            </div>
          ))}
          {error && <div className="alert alert-error">{String(error)}</div>}
          <button className="btn" type="submit">
            Register
          </button>
        </form>
        <p className="hint">
          Already have an account? <a href="/login">Log in</a>
        </p>
      </div>
    </div>
  );
}
