"use client";

// app/login/page.js
//
// ⚠️ INTENTIONALLY VULNERABLE — TRAINING/TESTING USE ONLY ⚠️
//
// VULNERABILITY: JWT is stored in localStorage instead of an httpOnly,
// Secure, SameSite cookie. Any XSS anywhere on the site can read
// localStorage and steal the token. Also no CSRF protection is relevant
// here since it's not cookie-based, but the token can't be revoked and
// never expires (see lib/auth.js), and there's no rate limiting on the
// login API this form calls (see app/api/auth/login/route.js).

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function LoginPage() {
  const [email, setEmail] = useState("alice@example.com");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const router = useRouter();

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");

    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();

    if (!res.ok) {
      setError(data.error || "Login failed");
      return;
    }

    // VULNERABILITY: token + full user object (including is_admin) saved to
    // localStorage, readable by any script on the page.
    localStorage.setItem("token", data.token);
    localStorage.setItem("user", JSON.stringify(data.user));

    router.push(`/profile?id=${data.user.id}`);
  }

  return (
    <div className="page page-form">
      <div className="card">
        <h1 className="page-title">Sign in</h1>
        <div className="alert alert-warning" style={{ fontSize: 12 }}>
          Demo accounts: alice@example.com / password123, bob@example.com / letmein,
          admin@example.com / admin123
        </div>
        <form onSubmit={handleSubmit}>
          <div className="field">
            <label>Email</label>
            <input value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div className="field">
            <label>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          {error && <div className="alert alert-error">{error}</div>}
          <button className="btn" type="submit">
            Log in
          </button>
        </form>
        <p className="hint">
          No account? <a href="/register">Register</a>
        </p>
      </div>
    </div>
  );
}
