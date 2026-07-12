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
    <main style={{ maxWidth: 360, margin: "80px auto", fontFamily: "sans-serif" }}>
      <h1>Sign in</h1>
      <p style={{ fontSize: 12, color: "#b00" }}>
        Demo accounts: alice@example.com / password123, bob@example.com / letmein,
        admin@example.com / admin123
      </p>
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: 12 }}>
          <label>Email</label>
          <br />
          <input
            style={{ width: "100%", padding: 8 }}
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>
        <div style={{ marginBottom: 12 }}>
          <label>Password</label>
          <br />
          <input
            style={{ width: "100%", padding: 8 }}
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        {error && <p style={{ color: "red" }}>{error}</p>}
        <button style={{ width: "100%", padding: 10 }} type="submit">
          Log in
        </button>
      </form>
      <p style={{ marginTop: 16 }}>
        No account? <a href="/register">Register</a>
      </p>
    </main>
  );
}
